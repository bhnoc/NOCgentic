"""
Hunter Agent -- port 8010

Proactive threat-hunting scheduler for NOCgentic. Maintains a registry of
MITRE-mapped hunt templates and runs them on an interval by delegating to
the investigator service. Findings are stored as hunt_runs and linked to
the originating investigation run_id.

Port: 8010
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from fastapi import FastAPI, HTTPException, Query

# ---------------------------------------------------------------------------
# sys.path bootstrap -- mirror triage pattern exactly
# ---------------------------------------------------------------------------
_SHARED = str(Path(__file__).resolve().parents[2] / "shared")
if _SHARED not in sys.path:
    sys.path.insert(0, _SHARED)

import store  # noqa: E402
from hunt_templates import HUNT_TEMPLATES  # noqa: E402

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("hunter")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
INVESTIGATOR_URL = os.environ.get("INVESTIGATOR_URL", "http://investigator:8007")
SCHED_TICK_SECONDS = int(os.environ.get("SCHED_TICK_SECONDS", "300"))
HUNTER_AUTORUN = os.environ.get("HUNTER_AUTORUN", "1") != "0"

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

app = FastAPI(title="BHNOCgentic Hunter", version="0.1.0")

_investigator_client: InvestigatorClient | None = None

# hnt-2: in-process set of hunt_ids currently executing (best-effort single-process guard)
# Multi-replica deployments would need a DB advisory lock instead.
# s2-06: This set has no TTL — a process crash while a hunt is in-flight leaves no orphaned
# entry (the set is process-local and discarded on restart). The investigator client uses a
# 120s request timeout (see HttpInvestigatorClient), so the worst-case in-flight window is
# bounded. In a multi-replica setup, replace this set with a PG advisory lock or a
# short-TTL distributed lock (e.g. Redis SETNX with TTL ~timeout+buffer).
_inflight_hunts: set[str] = set()


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
    """Initialise schema, register hunt templates, and optionally start the scheduler."""
    try:
        store.init_schema()
        logger.info("hunter: schema initialised")
    except Exception as exc:  # noqa: BLE001
        logger.warning("hunter: could not init schema (PG unavailable?): %s", exc)

    try:
        store.register_hunts(HUNT_TEMPLATES)
        logger.info("hunter: %d hunt templates registered", len(HUNT_TEMPLATES))
    except Exception as exc:  # noqa: BLE001
        logger.warning("hunter: could not register hunt templates: %s", exc)

    if HUNTER_AUTORUN:
        asyncio.create_task(_scheduler_loop())
        logger.info("hunter: background scheduler started (tick=%ds)", SCHED_TICK_SECONDS)
    else:
        logger.info("hunter: autorun disabled (HUNTER_AUTORUN=0)")


# ---------------------------------------------------------------------------
# Core run logic (reusable by endpoint and scheduler)
# ---------------------------------------------------------------------------


async def _run_hunt_core(hunt: dict, client: InvestigatorClient) -> dict:
    """Execute a single hunt via the investigator client and record the result.

    On investigator failure raises the original exception WITHOUT marking the
    hunt as run (so it retries on the next scheduler tick).

    hnt-2: Checks the in-process _inflight_hunts set before running. If the hunt
    is already in-flight (within this process), raises RuntimeError with a 409-style
    message. NOTE: multi-replica safety requires a DB advisory lock.

    hnt-3: Uses record_hunt_run_and_mark for atomic record + last_run_at update.

    Returns the hunt_run result dict.
    """
    hunt_id = hunt["id"]

    # hnt-2: best-effort single-process concurrency guard
    if hunt_id in _inflight_hunts:
        raise RuntimeError(f"hunt {hunt_id} already in-flight (409: concurrent run skipped)")

    _inflight_hunts.add(hunt_id)
    try:
        # Call investigator -- may raise; caller handles 502 conversion
        finding_resp = await client.investigate(hunt["hunt_query"], window_hours=24)

        finding = finding_resp.get("finding", {})
        run_id: str | None = finding_resp.get("run_id")
        verdict: str | None = finding.get("verdict")
        severity: str | None = finding.get("severity")
        summary: str | None = finding.get("summary")
        mitre_technique: str = hunt["mitre_technique"]

        # hnt-3: atomic record + mark in one transaction
        now = datetime.now(timezone.utc)
        hunt_run_id = store.record_hunt_run_and_mark(
            hunt_id=hunt_id,
            investigation_run_id=run_id,
            verdict=verdict,
            severity=severity,
            mitre_technique=mitre_technique,
            summary=summary,
            ran_at=now,
        )
    finally:
        _inflight_hunts.discard(hunt_id)

    return {
        "hunt_run_id": hunt_run_id,
        "investigation_run_id": run_id,
        "finding": finding,
        "mitre_technique": mitre_technique,
    }


# ---------------------------------------------------------------------------
# Pure scheduler tick (injected now + client -- deterministic and testable)
# ---------------------------------------------------------------------------


async def scheduler_tick(now: datetime, client: InvestigatorClient) -> list[str]:
    """Run all due hunts and return the list of hunt ids that ran.

    Pure in the sense that 'due' is computed from the injected `now` with no
    wall-clock calls inside this function. The live loop passes
    datetime.now(timezone.utc); tests pass a fixed datetime.

    Each hunt is attempted independently. Errors are logged and do NOT prevent
    other hunts from running.
    """
    due = store.due_hunts(now)
    ran: list[str] = []

    for hunt in due:
        try:
            await _run_hunt_core(hunt, client)
            ran.append(hunt["id"])
            logger.info("hunter: scheduler ran hunt %s", hunt["id"])
        except Exception as exc:  # noqa: BLE001
            logger.error("hunter: scheduler failed hunt %s: %s", hunt["id"], exc)

    return ran


# ---------------------------------------------------------------------------
# Background scheduler loop
# ---------------------------------------------------------------------------


async def _scheduler_loop() -> None:
    """Background asyncio task: run scheduler_tick every SCHED_TICK_SECONDS.

    hnt-4: run one tick immediately on startup (before the first sleep) so
    hunts are not delayed a full interval on fresh deploy.
    """
    while True:
        # hnt-4: tick first, then sleep — inverted from the original sleep-first order.
        try:
            client = _get_investigator_client()
            now = datetime.now(timezone.utc)
            ran = await scheduler_tick(now, client)
            if ran:
                logger.info("hunter: scheduler tick ran %d hunt(s): %s", len(ran), ran)
        except Exception as exc:  # noqa: BLE001
            logger.error("hunter: scheduler loop error (continuing): %s", exc)
        await asyncio.sleep(SCHED_TICK_SECONDS)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
    return {"status": "ok", "service": "hunter", "autorun": HUNTER_AUTORUN}


@app.get("/hunts")
async def list_hunts_endpoint() -> dict:
    hunts = store.list_hunts()
    return {"count": len(hunts), "hunts": _serialize_datetimes(hunts)}


# NOTE: /hunts/runs must be defined BEFORE /hunts/{id} or FastAPI routes
# "runs" as a literal id match. Keep this ordering.
@app.get("/hunts/runs")
async def list_runs_endpoint(
    hunt_id: str | None = Query(default=None),
    since: str | None = Query(default=None),
) -> dict:
    """Return recent hunt runs, optionally filtered by hunt_id and/or since (ISO timestamp)."""
    since_dt: datetime | None = None
    if since is not None:
        try:
            since_dt = datetime.fromisoformat(since)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"invalid since: {exc}")

    runs = store.list_hunt_runs(hunt_id=hunt_id, since=since_dt)
    return {"count": len(runs), "runs": _serialize_datetimes(runs)}


@app.get("/hunts/{hunt_id}")
async def get_hunt_endpoint(hunt_id: str) -> dict:
    hunt = store.get_hunt(hunt_id)
    if hunt is None:
        raise HTTPException(status_code=404, detail=f"hunt not found: {hunt_id}")
    return _serialize_datetimes(hunt)


@app.post("/hunts/{hunt_id}/run")
async def run_hunt_endpoint(hunt_id: str, force: bool = Query(default=False)) -> dict:
    """Run a hunt immediately (manual trigger).

    hnt-5: Disabled hunts are rejected with 409 unless ?force=true is passed.
    This prevents accidental runs of hunts the operator has intentionally disabled
    while still allowing an explicit manual override when needed.
    """
    hunt = store.get_hunt(hunt_id)
    if hunt is None:
        raise HTTPException(status_code=404, detail=f"hunt not found: {hunt_id}")

    # hnt-5: reject disabled hunt unless ?force=true
    if not hunt.get("enabled", True) and not force:
        raise HTTPException(
            status_code=409,
            detail=f"hunt disabled: {hunt_id}. Pass ?force=true to override."
        )

    client = _get_investigator_client()

    try:
        result = await _run_hunt_core(hunt, client)
    except Exception as exc:  # noqa: BLE001
        logger.error("hunter: manual run failed for hunt %s: %s", hunt_id, exc)
        raise HTTPException(status_code=502, detail=f"investigator unavailable: {exc}")

    return _serialize_datetimes(result)


@app.post("/hunts/{hunt_id}/enable")
async def enable_hunt(hunt_id: str) -> dict:
    updated = store.set_hunt_enabled(hunt_id, enabled=True)
    if updated is None:
        raise HTTPException(status_code=404, detail=f"hunt not found: {hunt_id}")
    return _serialize_datetimes(updated)


@app.post("/hunts/{hunt_id}/disable")
async def disable_hunt(hunt_id: str) -> dict:
    updated = store.set_hunt_enabled(hunt_id, enabled=False)
    if updated is None:
        raise HTTPException(status_code=404, detail=f"hunt not found: {hunt_id}")
    return _serialize_datetimes(updated)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8010, log_level="info")
