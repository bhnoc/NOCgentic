"""
Root-Cause Agent — port 8006

Agentic root-cause investigation for NOCgentic. Ties together:
  - agents/shared/templating.py   (Drain3-backed, deterministic)
  - agents/shared/embeddings.py   (stub or Gemini)
  - agents/shared/store.py        (psycopg3 + pgvector)
  - agents/shared/llm_client.py   (LLM prose ONLY — data/voice split)

Data/voice split (strict):
  CODE owns: anomaly detection, spike selection, clustering, similarity,
             deploy-marker correlation, verdict / root_cause_hint, recommendations.
  LLM writes: the 2–3 sentence prose narrative ONLY (step 8 of the loop).

Port: 8006
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# sys.path bootstrap — mirror athena-hunter pattern exactly
# ---------------------------------------------------------------------------
_SHARED = str(Path(__file__).resolve().parents[2] / "shared")
if _SHARED not in sys.path:
    sys.path.insert(0, _SHARED)

# Suppress telemetry network noise; other agents do the same when OTEL_ENABLED=false
from telemetry import init_telemetry  # noqa: E402

init_telemetry(service_name="bhnocgentic-root-cause")

from embeddings import embed, is_stub  # noqa: E402
from llm_client import llm_complete    # noqa: E402
from templating import TemplateMiner   # noqa: E402
import store                           # noqa: E402

# s2-05: sentinel exception class so callers can catch auth-class embed failures
class EmbedAuthError(RuntimeError):
    """Raised when embed() surfaces an auth/config error to signal 503."""
    pass


async def _embed_safe(texts: list[str]) -> list[list[float]]:
    """Wrap embed() so that an auth raise becomes EmbedAuthError.

    All other exceptions propagate unchanged (they're already handled
    by the call sites or will become 500s as before).
    """
    try:
        return await embed(texts)
    except Exception as exc:
        # Only re-wrap if it's an auth error (embed() already re-raises auth errors).
        # We detect this by checking that it's NOT a stub fallback scenario — the
        # simplest approach: if embed() raised, it was an auth error (embed only raises
        # on auth; transient errors are caught internally and fall back to stub).
        raise EmbedAuthError(str(exc)) from exc

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("root-cause")

# ---------------------------------------------------------------------------
# Module-level TemplateMiner (single instance, in-memory)
# Shared miner for /ingest only; /investigate uses a fresh per-call instance.
# ---------------------------------------------------------------------------
_miner: TemplateMiner = TemplateMiner()


# ---------------------------------------------------------------------------
# Standalone densify+detect helper (testable without Athena)
# ---------------------------------------------------------------------------

def _densify_and_score(
    sparse_rows: list[dict],  # [{"sig": str, "bucket_epoch": int, "n": float}]
    t0: float,
    t1: float,
) -> list[dict]:
    """Given sparse (sig, bucket, count) rows and a window [t0, t1], return
    spike dicts with densified series, correct mean/std, z, and novel flag.

    rc-1 fix: builds the full hourly grid and fills missing hours with 0.
    rc-2 fix: guards std==0 with nonzero_bucket / absolute count thresholds.
    """
    import math as _math
    from collections import defaultdict

    sparse: dict[str, dict[int, float]] = defaultdict(dict)
    for row in sparse_rows:
        sig = row["sig"]
        bkey = int(row["bucket_epoch"] // 3600) * 3600  # normalize to hour
        sparse[sig][bkey] = float(row.get("n", 0))

    first_bucket = int(t0 // 3600) * 3600
    last_bucket = int(t1 // 3600) * 3600
    all_buckets = list(range(first_bucket, last_bucket + 3600, 3600))
    n_buckets = len(all_buckets)

    results = []
    for sig, bucket_map in sparse.items():
        counts = [bucket_map.get(b, 0.0) for b in all_buckets]
        if not counts:
            continue
        mean = sum(counts) / len(counts)
        if len(counts) > 1:
            variance = sum((c - mean) ** 2 for c in counts) / len(counts)
            std = _math.sqrt(variance)
        else:
            std = 0.0

        max_count = max(counts)
        max_idx = counts.index(max_count)
        peak_bucket_epoch = all_buckets[max_idx]  # rc-4: epoch of the highest-count hour
        nonzero_buckets = sum(1 for c in counts if c > 0)

        if std == 0:
            if nonzero_buckets < 2 or max_count < 5:
                z = 0.0
            else:
                z = 99.0
        else:
            z = (max_count - mean) / std

        half = n_buckets // 2
        novel = half > 0 and all(c == 0 for c in counts[:half]) and max_count > 0

        results.append({
            "signature": sig,
            "count": int(max_count),
            "baseline": round(mean, 2),
            "z": round(z, 2),
            "novel": novel,
            "counts": counts,
            "nonzero_buckets": nonzero_buckets,
            "peak_bucket": peak_bucket_epoch,  # rc-4: tight marker correlation window
        })

    return results

# ---------------------------------------------------------------------------
# AnomalySource protocol + implementations
# ---------------------------------------------------------------------------


@runtime_checkable
class AnomalySource(Protocol):
    """Seam for anomaly detection — prod uses Athena; tests inject a fixture."""

    async def detect(self, window_hours: int) -> dict:
        """Return {"spikes":[...], "window":{"t0":..,"t1":..}}"""
        ...

    async def fetch_events(self, signature: str, t0: float, t1: float) -> list[str]:
        """Return raw event lines for the spiking signature in the window."""
        ...


class AthenaAnomalySource:
    """Production implementation — queries suricata_corelight via Athena."""

    async def detect(self, window_hours: int) -> dict:
        import math
        import time
        from athena_client import execute_query, date_partitions

        now = time.time()
        t0 = now - window_hours * 3600
        t1 = now

        parts = date_partitions(window_hours)
        if len(parts) == 1:
            part_clause = f"dt = '{parts[0]}'"
        else:
            part_clause = f"dt IN ({', '.join(repr(d) for d in parts)})"

        sql = f"""
        SELECT alert_signature,
               date_trunc('hour', from_unixtime(ts)) AS bucket,
               count(*) AS n
        FROM suricata_corelight
        WHERE ({part_clause} AND ts >= {t0:.0f} AND ts <= {t1:.0f})
          AND alert_severity <= 2
          AND alert_signature NOT LIKE 'ET INFO%'
        GROUP BY 1, 2
        ORDER BY 2
        """

        try:
            rows, _meta = await execute_query(sql)
        except Exception as exc:
            logger.warning("Athena detect query failed: %s", exc)
            return {"spikes": [], "window": {"t0": t0, "t1": t1}}

        if not rows:
            return {"spikes": [], "window": {"t0": t0, "t1": t1}}

        # Build per-signature sparse map: {sig -> {bucket_epoch -> count}}
        from collections import defaultdict
        import math as _math

        sparse: dict[str, dict[int, float]] = defaultdict(dict)
        for row in rows:
            sig = row.get("alert_signature") or ""
            try:
                n = float(row.get("n") or 0)
            except (ValueError, TypeError):
                n = 0.0
            # Normalize bucket to an integer hour epoch for easy enumeration
            bucket = row.get("bucket")
            if bucket is None:
                continue
            # bucket may be a datetime or a string; convert to epoch int (truncated hour)
            if hasattr(bucket, "timestamp"):
                bkey = int(bucket.timestamp())
            else:
                try:
                    from datetime import datetime as _dt
                    bkey = int(_dt.fromisoformat(str(bucket)).timestamp())
                except Exception:
                    continue
            sparse[sig][bkey] = n

        # Build the full list of expected hourly buckets across [t0, t1]
        # bucket = hour-truncated epoch: floor(ts / 3600) * 3600
        first_bucket = int(t0 // 3600) * 3600
        last_bucket = int(t1 // 3600) * 3600
        all_buckets = list(range(first_bucket, last_bucket + 3600, 3600))
        n_buckets = len(all_buckets)  # >= 1

        # Compute mean + stddev per signature; flag spikes
        spikes = []
        for sig, bucket_map in sparse.items():
            # rc-1: DENSIFY — build the full series with 0 for missing hours
            counts = [bucket_map.get(b, 0.0) for b in all_buckets]

            if not counts:
                continue

            mean = sum(counts) / len(counts)
            if len(counts) > 1:
                variance = sum((c - mean) ** 2 for c in counts) / len(counts)
                std = _math.sqrt(variance)
            else:
                std = 0.0

            max_count = max(counts)
            max_idx = counts.index(max_count)
            peak_bucket_epoch = all_buckets[max_idx]  # rc-4: epoch of the highest-count hour

            # rc-2: guard std=0 / insufficient baseline before assigning z=99
            nonzero_buckets = sum(1 for c in counts if c > 0)
            if std == 0:
                if nonzero_buckets < 2 or max_count < 5:
                    # Insufficient baseline to z-score reliably
                    z = 0.0
                else:
                    z = 99.0
            else:
                z = (max_count - mean) / std

            # Novel: signature only appears in second half of window (not in baseline)
            half = n_buckets // 2
            novel = half > 0 and all(c == 0 for c in counts[:half]) and max_count > 0

            if z >= 2.0 or novel:
                spikes.append({
                    "signature": sig,
                    "count": int(max_count),
                    "baseline": round(mean, 2),
                    # rc-4: tight marker correlation — use peak bucket epoch, not full window
                    "t0": peak_bucket_epoch - 300,   # 5 min pre-slack before peak hour
                    "t1": peak_bucket_epoch + 3600,  # one full hour after peak bucket start
                    "z": round(z, 2),
                    "peak_bucket": peak_bucket_epoch,
                })

        # Sort by z desc
        spikes.sort(key=lambda s: s["z"], reverse=True)
        return {"spikes": spikes, "window": {"t0": t0, "t1": t1}}

    async def fetch_events(self, signature: str, t0: float, t1: float) -> list[str]:
        from athena_client import execute_query, date_partitions, sanitize_value
        import time

        parts = date_partitions(int((t1 - t0) / 3600) + 1)
        if len(parts) == 1:
            part_clause = f"dt = '{parts[0]}'"
        else:
            part_clause = f"dt IN ({', '.join(repr(d) for d in parts)})"

        # rc-10: use shared sanitize_value() for consistent escaping.
        # sanitize_sql (called inside execute_query) rejects '--' and '/*' comment
        # sequences, so signatures containing '--' (e.g. "ET SCAN Nmap --script")
        # would cause sanitize_sql to raise ValueError and silently return [].
        # Detect this case upfront and degrade gracefully with a warning rather
        # than losing all events.
        safe_sig = sanitize_value(signature)
        # Check whether the escaped signature would trigger sanitize_sql's comment check.
        # If so, fall back to a LIKE query without the comment-like text.
        import re as _re2
        _COMMENT_RE = _re2.compile(r"(--|/\*|\*/|#)")
        if _COMMENT_RE.search(safe_sig):
            logger.warning(
                "fetch_events: signature contains SQL-comment-like text (%r); "
                "falling back to prefix LIKE match to avoid sanitize_sql rejection.",
                signature,
            )
            # Truncate at first comment-like sequence for a safe prefix match.
            _comment_pos = _COMMENT_RE.search(safe_sig).start()
            _prefix = safe_sig[:_comment_pos].strip()
            if not _prefix:
                logger.warning("fetch_events: prefix is empty after stripping; returning []")
                return []
            # Use sanitize_like_value on the original prefix fragment, then build LIKE query.
            from athena_client import sanitize_like_value
            _safe_prefix = sanitize_like_value(signature[:signature.find(signature[_comment_pos:_comment_pos+2])])
            sql = f"""
        SELECT ts, alert_signature, alert_category, alert_severity,
               id_orig_h, id_resp_h, id_orig_p, id_resp_p, service
        FROM suricata_corelight
        WHERE ({part_clause} AND ts >= {t0:.0f} AND ts <= {t1:.0f})
          AND alert_signature LIKE '{_safe_prefix}%' ESCAPE '\\'
        ORDER BY ts DESC
        LIMIT 200
        """
        else:
            sql = f"""
        SELECT ts, alert_signature, alert_category, alert_severity,
               id_orig_h, id_resp_h, id_orig_p, id_resp_p, service
        FROM suricata_corelight
        WHERE ({part_clause} AND ts >= {t0:.0f} AND ts <= {t1:.0f})
          AND alert_signature = '{safe_sig}'
        ORDER BY ts DESC
        LIMIT 200
        """

        try:
            rows, _meta = await execute_query(sql)
        except Exception as exc:
            logger.warning("Athena fetch_events failed: %s", exc)
            return []

        lines = []
        for row in rows:
            parts_line = (
                f"suricata ts={row.get('ts','')} "
                f"sig={row.get('alert_signature','')} "
                f"cat={row.get('alert_category','')} "
                f"sev={row.get('alert_severity','')} "
                f"src={row.get('id_orig_h','')}:{row.get('id_orig_p','')} "
                f"dst={row.get('id_resp_h','')}:{row.get('id_resp_p','')} "
                f"svc={row.get('service','')}"
            )
            lines.append(parts_line)
        return lines


class FixtureAnomalySource:
    """Test fixture — inject canned spikes and event lines. No AWS creds needed."""

    def __init__(
        self,
        spikes: list[dict],
        events_by_sig: dict[str, list[str]],
        window: dict | None = None,
    ) -> None:
        self._spikes = spikes
        self._events_by_sig = events_by_sig
        self._window = window or {}

    async def detect(self, window_hours: int) -> dict:
        import time
        now = time.time()
        t0 = self._window.get("t0", now - window_hours * 3600)
        t1 = self._window.get("t1", now)
        # Stamp the fixture spikes with the actual window bounds
        for spike in self._spikes:
            spike.setdefault("t0", t0)
            spike.setdefault("t1", t1)
        return {
            "spikes": self._spikes,
            "window": {"t0": t0, "t1": t1},
        }

    async def fetch_events(self, signature: str, t0: float, t1: float) -> list[str]:
        return self._events_by_sig.get(signature, [])


# Module-level anomaly source (overridable for tests via app.state or direct assignment)
_anomaly_source: AnomalySource = AthenaAnomalySource()

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="BHNOCgentic Root-Cause", version="0.1.0")


@app.on_event("startup")
async def _startup():
    """Initialise the Postgres schema on startup (idempotent; logs if PG absent)."""
    try:
        store.init_schema()
        logger.info("root-cause: schema initialised")
    except Exception as exc:  # noqa: BLE001
        logger.warning("root-cause: could not init schema (PG unavailable?): %s", exc)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class RawEvent(BaseModel):
    raw: str = Field(..., max_length=10_000)
    source: str = "suricata"
    ts: float | None = None


class IngestRequest(BaseModel):
    events: list[RawEvent] | None = Field(default=None, max_length=5_000)
    from_athena: bool = False
    hours: int = 24


class IngestResponse(BaseModel):
    templates_upserted: int
    unique_templates: int
    events_seen: int


class SimilarResponse(BaseModel):
    templates: list[dict]
    incidents: list[dict]


class IncidentRequest(BaseModel):
    title: str
    summary: str
    root_cause: str
    resolution: str
    deploy_marker: str | None = None
    commit_sha: str | None = None


class IncidentResponse(BaseModel):
    id: str


class InvestigateRequest(BaseModel):
    query: str = ""
    window_hours: int = 24


class MarkerRequest(BaseModel):
    ts: str | float  # ISO string or epoch float
    kind: str
    ref: str
    commit_sha: str | None = None
    note: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _source_for_ingest(request: IngestRequest) -> AnomalySource:
    """Return the module-level source, but allow app.state override."""
    try:
        return app.state.anomaly_source
    except AttributeError:
        return _anomaly_source


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "root-cause", "embed_stub": is_stub()}


@app.post("/ingest", response_model=IngestResponse)
async def ingest(req: IngestRequest) -> IngestResponse:
    """Ingest raw events: cluster via Drain, embed unique templates, upsert to store."""
    raw_events: list[tuple[str, str]] = []  # (raw_text, source)

    if req.from_athena:
        source_impl = _source_for_ingest(req)
        window_hours = max(1, min(req.hours, 48))
        result = await source_impl.detect(window_hours)
        for spike in result.get("spikes", []):
            sig = spike.get("signature", "")
            t0 = spike.get("t0", 0)
            t1 = spike.get("t1", 0)
            lines = await source_impl.fetch_events(sig, t0, t1)
            for line in lines:
                raw_events.append((line, "athena"))
    elif req.events:
        for ev in req.events:
            raw_events.append((ev.raw, ev.source))

    if not raw_events:
        return IngestResponse(templates_upserted=0, unique_templates=0, events_seen=0)

    # Cluster all events; collect unique templates
    unique_templates: dict[str, dict] = {}  # template_str -> {template_id, sample, mask_keys, source}
    for raw_text, source in raw_events:
        result = _miner.add(raw_text)
        t_str = result["template"]
        if t_str not in unique_templates:
            unique_templates[t_str] = {
                "template_id": result["template_id"],
                "sample": raw_text,
                "mask_keys": result["params"],
                "source": source,
            }

    events_seen = len(raw_events)
    unique_count = len(unique_templates)

    # Embed unique templates in one batch
    template_texts = list(unique_templates.keys())
    try:
        embeddings = await _embed_safe(template_texts)
    except EmbedAuthError as exc:
        raise HTTPException(status_code=503, detail=f"embedding provider unavailable: {exc}")

    # Upsert each unique template
    upserted = 0
    for t_str, emb in zip(template_texts, embeddings):
        meta = unique_templates[t_str]
        store.upsert_template(
            template=t_str,
            sample=meta["sample"],
            mask_keys=meta["mask_keys"],
            source=meta["source"],
            embedding=emb,
        )
        upserted += 1

    return IngestResponse(
        templates_upserted=upserted,
        unique_templates=unique_count,
        events_seen=events_seen,
    )


@app.get("/similar", response_model=SimilarResponse)
async def similar(text: str, k: int = 5) -> SimilarResponse:
    """Embed text, return nearest templates and incidents."""
    try:
        embs = await _embed_safe([text])
    except EmbedAuthError as exc:
        raise HTTPException(status_code=503, detail=f"embedding provider unavailable: {exc}")
    emb = embs[0]
    templates = store.similar_templates(emb, k=k)
    incidents = store.similar_incidents(emb, k=k)
    # Serialize datetimes for JSON
    for t in templates:
        if t.get("last_seen") and hasattr(t["last_seen"], "isoformat"):
            t["last_seen"] = t["last_seen"].isoformat()
    return SimilarResponse(templates=templates, incidents=incidents)


@app.post("/incidents", response_model=IncidentResponse)
async def create_incident(req: IncidentRequest) -> IncidentResponse:
    """Record a resolved incident with its embedding."""
    text = f"{req.title} {req.summary} {req.root_cause}"
    try:
        embs = await _embed_safe([text])
    except EmbedAuthError as exc:
        raise HTTPException(status_code=503, detail=f"embedding provider unavailable: {exc}")
    emb = embs[0]
    inc_id = store.record_incident(
        title=req.title,
        summary=req.summary,
        root_cause=req.root_cause,
        resolution=req.resolution,
        embedding=emb,
        deploy_marker=req.deploy_marker,
        commit_sha=req.commit_sha,
    )
    return IncidentResponse(id=inc_id)


@app.post("/markers")
async def add_marker(req: MarkerRequest) -> dict:
    """Add a deploy marker for correlation."""
    if isinstance(req.ts, str):
        # Parse ISO string
        try:
            ts_dt = datetime.fromisoformat(req.ts.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Invalid ts: {req.ts!r}")
    else:
        ts_dt = datetime.fromtimestamp(req.ts, tz=timezone.utc)

    marker_id = store.add_deploy_marker(
        ts=ts_dt,
        kind=req.kind,
        ref=req.ref,
        commit_sha=req.commit_sha,
        note=req.note,
    )
    return {"id": marker_id}


@app.get("/runs/{run_id}")
async def get_run(run_id: str) -> dict:
    """Return the full run record + events."""
    try:
        result = store.get_run(run_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"run not found: {run_id}")
    # Serialize datetimes
    _serialize_run(result)
    return result


def _serialize_run(obj: Any) -> None:
    """Mutate a run dict to make all datetimes JSON-safe strings."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if hasattr(v, "isoformat"):
                obj[k] = v.isoformat()
            else:
                _serialize_run(v)
    elif isinstance(obj, list):
        for item in obj:
            _serialize_run(item)


# ---------------------------------------------------------------------------
# /investigate — the agentic loop
# ---------------------------------------------------------------------------

# Code-owned recommendation templates (chosen deterministically by verdict type)
_RECOMMENDATIONS: dict[str, str] = {
    "deploy_marker": (
        "Review the deploy or config change that preceded the spike. "
        "Roll back if the change introduced the anomalous pattern; "
        "otherwise annotate the marker as expected behavior."
    ),
    "similar_incident": (
        "Cross-reference the linked incident. "
        "Apply the previously effective resolution. "
        "Validate that the remediation is still effective against this variant."
    ),
    "unknown": (
        "Isolate affected source IPs in the spike window. "
        "Escalate for manual review if the signature is high-severity. "
        "Ingest additional context and re-run investigation."
    ),
}

# Severity map from Suricata integer (1=highest)
def _map_severity(z: float, sig_count: int) -> str:
    if z >= 10 or sig_count >= 500:
        return "critical"
    if z >= 5 or sig_count >= 100:
        return "high"
    if z >= 2 or sig_count >= 20:
        return "medium"
    return "low"


@app.post("/investigate")
async def investigate(req: InvestigateRequest) -> dict:
    """Full agentic root-cause investigation loop."""
    window_hours = max(1, min(req.window_hours, 48))

    # Resolve anomaly source
    source: AnomalySource
    try:
        source = app.state.anomaly_source
    except AttributeError:
        source = _anomaly_source

    # --- 1. Start run ---
    run_id = store.start_run("root_cause", {"query": req.query, "window_hours": window_hours})
    try:
        return await _run_loop(run_id, req.query, window_hours, source)
    except Exception as exc:
        logger.exception("investigate loop failed: %s", exc)
        store.finish_run(run_id, "failed", {"error": str(exc)})
        raise HTTPException(status_code=500, detail=str(exc))


async def _run_loop(
    run_id: str,
    query: str,
    window_hours: int,
    source: AnomalySource,
) -> dict:
    from datetime import timedelta

    # --- 1. Plan ---
    store.emit(run_id, "plan", {
        "steps": [
            "detect_anomaly",
            "fetch_events",
            "cluster",
            "recall",
            "correlate",
            "verdict",
            "synthesis",
        ]
    })

    # --- 2. Anomaly detection ---
    anomaly = await source.detect(window_hours)
    spikes = anomaly.get("spikes", [])
    window = anomaly.get("window", {})
    t0_epoch = window.get("t0", 0.0)
    t1_epoch = window.get("t1", 0.0)
    store.emit(run_id, "anomaly_detected", {"spikes": spikes, "window": window})

    if not spikes:
        finding = {
            "id": run_id,
            "title": "Baseline nominal",
            "severity": "low",
            "category": "no_anomaly",
            "summary": "No anomalous signatures detected in the requested window.",
            "root_cause": "no anomaly",
            "recommendation": "No action required; traffic appears within baseline.",
            "run_id": run_id,
            "window": window,
        }
        store.emit(run_id, "verdict", {"assessment": "no anomaly"})
        store.finish_run(run_id, "completed", finding)
        return {"run_id": run_id, "finding": finding, "evidence": {"spikes": [], "events_sampled": []}}

    # --- 3. Top spike + fetch events ---
    # rc-6: use query to bias spike selection toward matching signatures.
    # If the query contains an IP or a signature substring, prefer spikes where
    # the signature contains that text (case-insensitive substring match).
    # Fall back to z-sorted top spike when no match or query is empty.
    import re as _re
    top_spike = spikes[0]  # default: highest z
    if query:
        # Extract candidate match tokens from the query: IPs and multi-char words
        _ip_re = _re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
        _word_re = _re.compile(r"\b[A-Za-z0-9_\-\.]{3,}\b")
        _query_tokens = _ip_re.findall(query) + _word_re.findall(query)
        _query_tokens_lower = [t.lower() for t in _query_tokens]
        # Score each spike: count how many query tokens appear in the signature
        def _query_score(spike: dict) -> int:
            sig_lower = spike.get("signature", "").lower()
            return sum(1 for t in _query_tokens_lower if t in sig_lower)
        _scored = sorted(spikes, key=lambda s: (_query_score(s), s.get("z", 0.0)), reverse=True)
        top_spike = _scored[0]
    sig = top_spike["signature"]
    spike_t0 = top_spike.get("t0", t0_epoch)
    spike_t1 = top_spike.get("t1", t1_epoch)

    store.emit(run_id, "tool_call", {"tool": "fetch_events", "signature": sig})
    events = await source.fetch_events(sig, spike_t0, spike_t1)
    store.emit(run_id, "tool_result", {"count": len(events)})

    # --- 4. Cluster events ---
    # Use a fresh per-investigation TemplateMiner to avoid cross-request contamination.
    # Template IDs in the store use sha1(template) so stability is content-based,
    # not dependent on the in-memory miner's cluster IDs.
    _inv_miner = TemplateMiner()
    template_results = []
    for ev in events:
        r = _inv_miner.add(ev)
        template_results.append(r)

    # Find dominant template (most common template_id)
    from collections import Counter
    if template_results:
        tid_counts = Counter(r["template_id"] for r in template_results)
        dominant_tid, _ = tid_counts.most_common(1)[0]
        dominant_template = next(
            r["template"] for r in template_results if r["template_id"] == dominant_tid
        )
    else:
        # Fallback: use signature as template
        dominant_tid = sig[:16]
        dominant_template = sig

    # Collect unique templates for the emit
    seen_tids: set[str] = set()
    unique_templates_list = []
    for r in template_results:
        if r["template_id"] not in seen_tids:
            seen_tids.add(r["template_id"])
            unique_templates_list.append({
                "template_id": r["template_id"],
                "template": r["template"],
                "cluster_size": r["cluster_size"],
            })

    store.emit(run_id, "cluster", {
        "templates": unique_templates_list,
        "dominant": dominant_template,
    })

    # Embed dominant template (needed for both recall and upsert)
    try:
        dom_embs = await _embed_safe([dominant_template])
    except EmbedAuthError as exc:
        _embed_err = str(exc)
        store.emit(run_id, "error", {"stage": "embed", "reason": _embed_err})
        store.finish_run(run_id, "failed", {"error": _embed_err})
        raise HTTPException(status_code=503, detail=f"embedding provider unavailable: {_embed_err}")
    dom_emb = dom_embs[0]

    # --- 5. Recall: similar templates + incidents (BEFORE upsert to avoid self-match) ---
    similar_tmpls = store.similar_templates(dom_emb, k=5)
    similar_incs = store.similar_incidents(dom_emb, k=5)

    # Upsert dominant template AFTER recall so it doesn't appear as its own top match
    store.upsert_template(
        template=dominant_template,
        sample=events[0] if events else sig,
        mask_keys={},
        source="suricata",
        embedding=dom_emb,
    )
    # Serialize datetimes
    for t in similar_tmpls:
        if t.get("last_seen") and hasattr(t["last_seen"], "isoformat"):
            t["last_seen"] = t["last_seen"].isoformat()

    store.emit(run_id, "recall", {
        "similar_incidents": similar_incs,
        "similar_templates": similar_tmpls,
    })

    # --- 6. Correlate deploy markers ---
    # rc-4: if the spike has a peak_bucket, use a tight window around that peak
    # (peak_bucket .. peak_bucket+1h, minus a small pre-slack) so marker correlation
    # is anchored to the actual spiking hour rather than the whole investigation window.
    peak_bucket = top_spike.get("peak_bucket")
    if peak_bucket is not None:
        # tight window: [peak_bucket - 5min pre-slack, peak_bucket + 1h]
        corr_t0 = peak_bucket - 300
        corr_t1 = peak_bucket + 3600
    else:
        # fallback: use spike window bounds (original behavior)
        corr_t0 = spike_t0 - 3600
        corr_t1 = spike_t1
    t0_dt = datetime.fromtimestamp(corr_t0, tz=timezone.utc)
    t1_dt = datetime.fromtimestamp(corr_t1, tz=timezone.utc)
    markers = store.markers_near(t0_dt, t1_dt)

    # Serialize marker datetimes
    for m in markers:
        if m.get("ts") and hasattr(m["ts"], "isoformat"):
            m["ts"] = m["ts"].isoformat()

    store.emit(run_id, "correlate", {"markers": markers})

    # --- Code-computed root_cause_hint (DATA, not LLM) ---
    root_cause_hint: str
    correlated_marker: dict | None = None
    nearest_incident: dict | None = None
    nearest_distance: float = 1.0
    hint_type: str = "unknown"

    # rc-11: check for a very-close incident match FIRST — if one exists with
    # distance < 0.15 it is a near-certain prior-incident match and should beat
    # an unrelated deploy marker. Only fall through to the marker if no such
    # strong match is present.
    _strong_incident: dict | None = None
    _strong_distance_threshold = 0.15
    if similar_incs:
        _candidate = similar_incs[0]
        if _candidate["distance"] < _strong_distance_threshold:
            _strong_incident = _candidate

    if _strong_incident is not None:
        # Strong prior-incident match beats any marker
        nearest_incident = _strong_incident
        nearest_distance = nearest_incident["distance"]
        root_cause_hint = nearest_incident.get("root_cause", "see linked incident")
        hint_type = "similar_incident"
    elif markers:
        # A marker sits in or just before the spike window → deploy correlation
        # markers_near returns ASC by ts; pick the one nearest (latest) to the spike.
        correlated_marker = markers[-1]
        ref = correlated_marker.get("ref", "")
        sha = correlated_marker.get("commit_sha", "")
        sha_str = f" (commit {sha})" if sha else ""
        root_cause_hint = f"deploy/config change: {ref}{sha_str}"
        hint_type = "deploy_marker"
    elif similar_incs:
        # Nearest incident below distance threshold → recall
        nearest_incident = similar_incs[0]
        nearest_distance = nearest_incident["distance"]
        if nearest_distance < 0.35:
            root_cause_hint = nearest_incident.get("root_cause", "see linked incident")
            hint_type = "similar_incident"
        else:
            root_cause_hint = "unknown"
            hint_type = "unknown"
    else:
        root_cause_hint = "unknown"
        hint_type = "unknown"

    # --- 7. Severity + verdict (code-computed) ---
    severity = _map_severity(top_spike.get("z", 0), top_spike.get("count", 0))
    store.emit(run_id, "verdict", {"severity": severity, "root_cause_hint": root_cause_hint})

    # FACTS dict (code-owned, verified)
    facts: dict[str, Any] = {
        "signature": sig,
        "severity": severity,
        "count": top_spike.get("count"),
        "z": top_spike.get("z"),
        "window": window,
        "dominant_template": dominant_template,
        "nearest_incident": nearest_incident,
        "nearest_distance": nearest_distance,
        "correlated_marker": correlated_marker,
        "root_cause_hint": root_cause_hint,
    }

    # --- 8. LLM prose synthesis (VOICE ONLY — no facts invented) ---
    prose_system = (
        "You are a NOC root-cause analyst. "
        "Given these VERIFIED FACTS (do not invent, do not add IPs or extra signatures), "
        "write a 2-3 sentence narrative suitable for a security operations report. "
        "Be concise and precise."
    )
    prose_user = json.dumps(facts, default=str)
    prose_fallback = (
        f"Signature '{sig}' showed a {severity}-severity spike "
        f"(count={top_spike.get('count')}, z={top_spike.get('z', 0.0):.1f}). "
        f"Root cause assessment: {root_cause_hint}."
    )

    try:
        prose = await llm_complete(
            system_prompt=prose_system,
            user_content=prose_user,
            max_tokens=512,
            temperature=0.1,
        )
        if not prose.strip():
            prose = prose_fallback
    except Exception as exc:  # noqa: BLE001
        logger.warning("LLM prose synthesis failed (%s); using fallback", exc)
        prose = prose_fallback

    store.emit(run_id, "synthesis", {"chars": len(prose)})

    # --- 9. Assemble finding and evidence ---
    recommendation = _RECOMMENDATIONS[hint_type]
    finding: dict[str, Any] = {
        "id": run_id,
        "title": f"{sig} anomaly",
        "severity": severity,
        "category": "anomaly",
        "summary": prose,
        "root_cause": root_cause_hint,
        "recommendation": recommendation,
        "run_id": run_id,
        "window": window,
    }
    evidence: dict[str, Any] = {
        "spikes": spikes,
        "dominant_template": dominant_template,
        "similar_incidents": similar_incs,
        "markers": markers,
        "events_sampled": events[:5],
    }

    store.finish_run(run_id, "completed", finding)
    return {"run_id": run_id, "finding": finding, "evidence": evidence}


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8006, log_level="info")
