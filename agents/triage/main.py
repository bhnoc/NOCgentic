"""
Triage Agent — port 8008

Autonomous triage hub for NOCgentic. Accepts incoming alerts, deduplicates them,
drives each through the bucket state machine by invoking the investigator service,
and exposes a priority-grouped queue for analyst review.

Port: 8008
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, Protocol

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# sys.path bootstrap — mirror investigator pattern exactly
# ---------------------------------------------------------------------------
_SHARED = str(Path(__file__).resolve().parents[2] / "shared")
if _SHARED not in sys.path:
    sys.path.insert(0, _SHARED)

import store  # noqa: E402

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("triage")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
INVESTIGATOR_URL = os.environ.get("INVESTIGATOR_URL", "http://investigator:8007")

# ---------------------------------------------------------------------------
# InvestigatorClient seam (Protocol + implementations)
# ---------------------------------------------------------------------------


class InvestigatorClient(Protocol):
    async def investigate(self, query: str, window_hours: int = 24) -> dict:
        ...


class HttpInvestigatorClient:
    """Production implementation: calls the real investigator over HTTP."""

    def __init__(self, base_url: str = INVESTIGATOR_URL) -> None:
        self.base_url = base_url.rstrip("/")

    async def investigate(self, query: str, window_hours: int = 24) -> dict:
        import httpx

        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                f"{self.base_url}/investigate",
                json={"query": query, "window_hours": window_hours},
            )
            resp.raise_for_status()
            return resp.json()


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="BHNOCgentic Triage", version="0.1.0")

_investigator_client: InvestigatorClient | None = None


def _get_investigator_client() -> InvestigatorClient:
    """Return injectable client (app.state override) or module-level singleton."""
    try:
        return app.state.investigator_client  # type: ignore[attr-defined]
    except AttributeError:
        pass
    global _investigator_client  # noqa: PLW0603
    if _investigator_client is None:
        _investigator_client = HttpInvestigatorClient()
    return _investigator_client


@app.on_event("startup")
async def _startup() -> None:
    """Initialise the Postgres schema on startup (idempotent; logs if PG absent)."""
    try:
        store.init_schema()
        logger.info("triage: schema initialised")
    except Exception as exc:  # noqa: BLE001
        logger.warning("triage: could not init schema (PG unavailable?): %s", exc)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class AlertIn(BaseModel):
    dedup_key: str | None = None
    severity: int = Field(default=0, ge=0)
    source_ip: str | None = None
    dest_ip: str | None = None
    alert_type: str | None = None
    signature: str | None = None
    raw_data: dict | None = None
    connector_source: str | None = None


class AlertBatchIn(BaseModel):
    alerts: list[AlertIn] | None = None
    # Single-alert fields (merged with alerts list for the batch path)
    dedup_key: str | None = None
    severity: int | None = None
    source_ip: str | None = None
    dest_ip: str | None = None
    alert_type: str | None = None
    signature: str | None = None
    raw_data: dict | None = None
    connector_source: str | None = None


class TransitionIn(BaseModel):
    to_bucket: str
    reason: str | None = None
    force: bool = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _derive_dedup_key(alert: AlertIn) -> str:
    """Deterministically derive a dedup key from alert fields if not supplied."""
    sig = alert.signature or ""
    src = alert.source_ip or ""
    dst = alert.dest_ip or ""
    return f"{sig}|{src}|{dst}"


def build_alert_query(alert: dict) -> str:
    """Build a deterministic NL investigation query from alert fields."""
    sig = alert.get("signature") or "unknown signature"
    src = alert.get("source_ip") or "unknown source"
    dst = alert.get("dest_ip") or "unknown destination"
    sev = alert.get("severity", 0)
    return (
        f"Investigate the alert '{sig}' from source {src} to {dst} "
        f"(severity {sev}) over the last 24 hours. "
        f"Is this a real threat or a false positive? "
        f"Query the relevant Corelight/Suricata tables."
    )


def _serialize_datetimes(obj: Any) -> Any:
    """Recursively convert datetimes to ISO strings for JSON serialisation."""
    if isinstance(obj, dict):
        return {k: _serialize_datetimes(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize_datetimes(v) for v in obj]
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    return obj


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "triage"}


@app.post("/alerts")
async def ingest_alerts(body: dict) -> dict:
    """Accept a single alert object or {alerts: [...]} batch.

    Each alert is upserted by dedup_key. Returns {ingested: N, ids: [...]}.
    """
    # Determine list of raw alert dicts
    if "alerts" in body and isinstance(body["alerts"], list):
        raw_alerts = body["alerts"]
    else:
        # Single alert — body itself is the alert
        raw_alerts = [body]

    ids: list[str] = []
    for raw in raw_alerts:
        alert = AlertIn(**{k: v for k, v in raw.items() if k in AlertIn.model_fields})
        if not alert.dedup_key:
            alert.dedup_key = _derive_dedup_key(alert)
        alert_id = store.upsert_alert(
            dedup_key=alert.dedup_key,
            severity=alert.severity or 0,
            source_ip=alert.source_ip,
            dest_ip=alert.dest_ip,
            alert_type=alert.alert_type,
            signature=alert.signature,
            raw_data=alert.raw_data,
            connector_source=alert.connector_source,
        )
        ids.append(alert_id)

    return {"ingested": len(ids), "ids": ids}


@app.get("/triage/queue")
async def triage_queue(bucket: str | None = None, severity: int | None = None) -> dict:
    """Return alerts filtered by bucket and/or minimum severity.

    Ordered by severity desc, last_seen desc.
    """
    alerts = store.list_alerts(bucket=bucket, severity_min=severity)
    return {"count": len(alerts), "alerts": _serialize_datetimes(alerts)}


@app.post("/triage/{alert_id}/investigate")
async def investigate_alert(alert_id: str) -> dict:
    """Run the investigator on an alert, file a verdict, and record two transitions."""
    alert = store.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"alert not found: {alert_id}")

    # Move to validating (must currently be in 'alerts')
    try:
        store.transition_alert(alert_id, "validating", reason="triage worker started")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    # Build query and call investigator
    query = build_alert_query(alert)
    client = _get_investigator_client()

    try:
        finding_resp = await client.investigate(query, window_hours=24)
    except Exception as exc:  # noqa: BLE001
        logger.error("investigate: investigator call failed: %s", exc)
        # Retry: transition back to 'alerts' so the worker can try again
        try:
            store.transition_alert(
                alert_id, "alerts",
                reason=f"investigator call failed: {exc}",
            )
        except ValueError:
            pass
        raise HTTPException(status_code=502, detail=f"investigator unavailable: {exc}")

    # CODE verdict mapping — never LLM
    finding_data = finding_resp.get("finding", {})
    evidence_data = finding_resp.get("evidence", {})
    run_id = finding_resp.get("run_id", "")

    verdict_bucket: str
    if (
        finding_data.get("verdict") == "threat"
        or evidence_data.get("high_signals")
    ):
        verdict_bucket = "validated_true_positive"
    else:
        verdict_bucket = "validated_false_positive"

    store.transition_alert(
        alert_id,
        verdict_bucket,
        reason="investigator verdict",
        investigation_run_id=run_id,
    )

    return {
        "alert_id": alert_id,
        "verdict_bucket": verdict_bucket,
        "investigation_run_id": run_id,
        "finding": finding_data,
    }


@app.get("/triage/{alert_id}")
async def get_triage_detail(alert_id: str) -> dict:
    """Return an alert with its full transition history and linked investigation run_ids."""
    alert = store.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"alert not found: {alert_id}")

    transitions = store.alert_transitions(alert_id)

    # Collect distinct investigation run_ids from transitions (preserving order)
    seen: set[str] = set()
    investigation_run_ids: list[str] = []
    for t in transitions:
        rid = t.get("investigation_run_id")
        if rid and rid not in seen:
            seen.add(rid)
            investigation_run_ids.append(rid)

    return {
        "alert": _serialize_datetimes(alert),
        "transitions": _serialize_datetimes(transitions),
        "investigation_run_ids": investigation_run_ids,
    }


@app.post("/triage/{alert_id}/transition")
async def manual_transition(alert_id: str, body: TransitionIn) -> dict:
    """Analyst override: move an alert to any bucket (with guard unless force=True)."""
    alert = store.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"alert not found: {alert_id}")

    try:
        result = store.transition_alert(
            alert_id,
            body.to_bucket,
            reason=body.reason,
            force=body.force,
        )
    except ValueError as exc:
        msg = str(exc)
        if msg.startswith("unknown bucket"):
            raise HTTPException(status_code=400, detail=msg)
        raise HTTPException(status_code=409, detail=msg)

    return result


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8008, log_level="info")
