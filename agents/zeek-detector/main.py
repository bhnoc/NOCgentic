"""
Zeek Detector — port 8007

Packages the APE-85/APE-86 research pipeline (Zeek parser → timing detector →
LangGraph classifier → findings) as a service for BH AI SOC.

  POST /analyze                    upload ssl.log / conn.log, get findings JSON
  GET  /analyses                   recent analyses (summaries, no findings)
  GET  /analyses/{id}              one analysis with its findings
  GET  /analyses/{id}/findings.csv CISO summary of that analysis
  GET  /findings                   findings across analyses, filterable
  GET  /health

Every analysis is persisted to SQLite (`ZEEK_DB_PATH`, a named volume in
compose) before the response is sent, so the response body and the stored
record are the same object.

Classifier modes (`ZEEK_CLASSIFIER_MODE`, or `?classifier=` per request):
  auto   llm when ANTHROPIC_API_KEY is set, otherwise rules  (default)
  llm    LangGraph ReAct agent on Claude, tools are the same three functions
  rules  the three tools called directly; deterministic, no network
An LLM failure on one cluster degrades that cluster to rules and marks it
`rules-fallback`; it never fails the upload.

What leaves the box in llm mode is exactly what the research prompt sent:
SNI hostnames, the cluster's IP pair and port, and the timing metrics. No
payload bytes exist in Zeek ssl/conn logs to leak. `ZEEK_DETECTOR_API_TOKEN`,
when set, gates every route except /health behind a bearer; the port is
internal-only in compose either way.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from pipeline import (  # noqa: E402
    ZeekParser,
    annotate_all_clusters,
    classify_all_clusters,
    findings_to_csv,
    generate_findings,
    resolve_mode,
)
from pipeline.classifier import DEFAULT_MODEL, MODES  # noqa: E402
from storage import FindingsStore  # noqa: E402

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
log = logging.getLogger("zeek-detector")

# ── Settings ─────────────────────────────────────────────────────────────────

DB_PATH = os.environ.get("ZEEK_DB_PATH", "/data/zeek-detector.db")
CLASSIFIER_MODE = os.environ.get("ZEEK_CLASSIFIER_MODE", "auto").strip().lower()
CLASSIFIER_MODEL = os.environ.get("ZEEK_CLASSIFIER_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL
MAX_UPLOAD_BYTES = int(os.environ.get("ZEEK_MAX_UPLOAD_BYTES", str(50 * 1024 * 1024)))
LLM_MAX_CLUSTERS = int(os.environ.get("ZEEK_LLM_MAX_CLUSTERS", "200"))
LLM_TIMEOUT = float(os.environ.get("ZEEK_LLM_TIMEOUT", "60"))
API_TOKEN = os.environ.get("ZEEK_DETECTOR_API_TOKEN", "").strip()

if CLASSIFIER_MODE not in MODES:
    raise RuntimeError(f"ZEEK_CLASSIFIER_MODE={CLASSIFIER_MODE!r} is not one of {MODES}")

_CHUNK = 1024 * 1024
ClassifierChoice = Literal["auto", "llm", "rules"]

store = FindingsStore(DB_PATH)


# ── Auth ─────────────────────────────────────────────────────────────────────

def require_token(request: Request) -> None:
    """Bearer check, active only when ZEEK_DETECTOR_API_TOKEN is set."""
    if not API_TOKEN:
        return
    header = request.headers.get("authorization", "")
    scheme, _, presented = header.partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(presented.strip(), API_TOKEN):
        raise HTTPException(status_code=401, detail="unauthorized")


# ── Models ───────────────────────────────────────────────────────────────────

class SourceFile(BaseModel):
    name: str
    log_type: Literal["ssl", "conn"]
    bytes: int
    sha256: str
    events: int


class ClassifierInfo(BaseModel):
    mode: str
    model: str | None = None


class Timeline(BaseModel):
    first_seen: str | None = None
    last_seen: str | None = None
    session_duration_seconds: float | None = None


class FindingMetrics(BaseModel):
    request_count: int = 0
    mean_inter_request_seconds: float | None = None
    timing_entropy_bits: float | None = None
    sawtooth_score: float = 0.0
    loop_score: float = 0.0


class Finding(BaseModel):
    finding_id: str
    host: str
    destination: str
    service_id: str
    service_name: str
    behavior_classification: str
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_level: str
    severity: str
    classifier_mode: str
    detected_patterns: list[str]
    evidence_chain: list[str]
    timeline: Timeline
    metrics: FindingMetrics
    server_names: list[str]
    recommendation: str
    narrative: str
    analysis_id: str | None = None
    analysis_created_at: str | None = None


class AnalysisSummary(BaseModel):
    analysis_id: str
    created_at: str
    classifier: ClassifierInfo
    source_files: list[SourceFile]
    event_count: int
    cluster_count: int
    duration_ms: int
    summary: dict[str, Any]
    metadata: dict[str, Any]


class AnalysisResponse(AnalysisSummary):
    findings: list[Finding]


# ── Upload handling ──────────────────────────────────────────────────────────

def _infer_log_type(filename: str, text: str) -> str | None:
    """ssl or conn from the filename, else from the log's own header/keys."""
    name = (filename or "").lower()
    if "ssl" in name:
        return "ssl"
    if "conn" in name:
        return "conn"
    # The column list is the stronger signal: ssl.log has server_name, conn.log
    # never does. #path is only a fallback, because a generator that copies the
    # conn header for both files is a real thing (our own fixtures do it).
    path_hint: str | None = None
    for line in text[:4096].splitlines():
        if line.startswith("#fields"):
            return "ssl" if "server_name" in line else "conn"
        if line.startswith("#path"):
            parts = line.split(None, 1)
            path = parts[1].strip().lower() if len(parts) > 1 else ""
            if path in ("ssl", "conn"):
                path_hint = path
        if line.startswith("{"):
            return "ssl" if '"server_name"' in line or '"version"' in line else "conn"
    return path_hint


async def _read_bounded(upload: UploadFile) -> bytes:
    """Read an upload in chunks, refusing once it passes MAX_UPLOAD_BYTES."""
    buf = bytearray()
    while True:
        chunk = await upload.read(_CHUNK)
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"{upload.filename or 'upload'} exceeds ZEEK_MAX_UPLOAD_BYTES={MAX_UPLOAD_BYTES}",
            )
    return bytes(buf)


async def _collect_uploads(files: list[UploadFile], ssl: UploadFile | None,
                           conn: UploadFile | None) -> list[tuple[str, str, bytes]]:
    """(name, log_type, raw) for every provided part, log_type resolved."""
    out: list[tuple[str, str, bytes]] = []
    for upload, forced in [(ssl, "ssl"), (conn, "conn")] + [(f, None) for f in files]:
        if upload is None:
            continue
        raw = await _read_bounded(upload)
        if not raw.strip():
            continue
        text_head = raw[:8192].decode("utf-8", errors="replace")
        log_type = forced or _infer_log_type(upload.filename or "", text_head)
        if log_type is None:
            raise HTTPException(
                status_code=422,
                detail=f"cannot tell whether {upload.filename or 'upload'} is ssl.log or conn.log; "
                       "name it accordingly or send it as the 'ssl' / 'conn' part",
            )
        out.append((upload.filename or f"{log_type}.log", log_type, raw))
    if not out:
        raise HTTPException(status_code=422, detail="no Zeek log content in the request")
    return out


# ── Pipeline ─────────────────────────────────────────────────────────────────

def _run_pipeline(uploads: list[tuple[str, str, bytes]], mode: str, model: str) -> dict[str, Any]:
    """Parse → cluster → time → classify → findings. Runs in the threadpool."""
    started = time.monotonic()
    parser = ZeekParser()
    events: list[dict] = []
    source_files: list[dict] = []
    for name, log_type, raw in uploads:
        parsed = parser.parse_string(raw.decode("utf-8", errors="replace"), log_type)
        events.extend(parsed)
        source_files.append({
            "name": name,
            "log_type": log_type,
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "events": len(parsed),
        })

    if not events:
        raise HTTPException(status_code=422, detail="no parseable Zeek events in the upload")

    clusters = parser.cluster(events)
    annotated_events, cluster_reports = annotate_all_clusters(clusters)

    report = {
        "cluster_reports": [
            {
                "src_host": r["cluster_key"][0],
                "dst_host": r["cluster_key"][1],
                "dst_port": r["cluster_key"][2],
                **r["metrics"],
                "patterns": r["patterns"],
            }
            for r in cluster_reports
        ],
        "events": annotated_events,
    }

    classifications, effective_mode = classify_all_clusters(
        report,
        mode=mode,
        model_name=model,
        llm_max_clusters=LLM_MAX_CLUSTERS,
        llm_timeout=LLM_TIMEOUT,
    )
    label = f"llm:{model}" if effective_mode == "llm" else "rules"
    findings_report = generate_findings(
        classifications,
        cluster_reports=report["cluster_reports"],
        events=annotated_events,
        classifier_label=label,
    )

    analysis = {
        "analysis_id": str(uuid.uuid4()),
        "created_at": datetime.now(tz=timezone.utc).isoformat(),
        "classifier": {"mode": effective_mode,
                       "model": model if effective_mode == "llm" else None},
        "source_files": source_files,
        "event_count": len(events),
        "cluster_count": len(cluster_reports),
        "duration_ms": int((time.monotonic() - started) * 1000),
        "summary": findings_report["summary"],
        "metadata": findings_report["metadata"],
        "findings": findings_report["findings"],
    }
    store.save_analysis(analysis)
    return analysis


# ── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(title="zeek-detector", version="1.0.0",
              description="Zeek AI-service detection pipeline for BH AI SOC")


@app.get("/health")
async def health() -> dict[str, Any]:
    try:
        counts = store.counts()
        db_ok = True
    except Exception as exc:  # noqa: BLE001
        log.error("health: store unreachable: %s", exc)
        counts, db_ok = {}, False
    return {
        "status": "ok" if db_ok else "degraded",
        "service": "zeek-detector",
        "db": {"path": DB_PATH, "ok": db_ok, **counts},
        "classifier": {
            "configured_mode": CLASSIFIER_MODE,
            "effective_mode": resolve_mode(CLASSIFIER_MODE),
            "model": CLASSIFIER_MODEL,
            "llm_max_clusters": LLM_MAX_CLUSTERS,
        },
        "auth": "bearer" if API_TOKEN else "none",
        "max_upload_bytes": MAX_UPLOAD_BYTES,
    }


@app.post("/analyze", response_model=AnalysisResponse, dependencies=[Depends(require_token)])
async def analyze(
    files: list[UploadFile] = File(default=[], description="Zeek logs; type inferred from name/header"),
    ssl: UploadFile | None = File(default=None, description="ssl.log (TSV or JSON)"),
    conn: UploadFile | None = File(default=None, description="conn.log (TSV or JSON)"),
    classifier: ClassifierChoice | None = Query(default=None, description="override ZEEK_CLASSIFIER_MODE"),
    model: str | None = Query(default=None, max_length=100, description="override ZEEK_CLASSIFIER_MODEL"),
) -> dict[str, Any]:
    mode = classifier or CLASSIFIER_MODE
    if resolve_mode(mode) == "llm" and not os.environ.get("ANTHROPIC_API_KEY"):
        raise HTTPException(status_code=503, detail="classifier=llm requested but ANTHROPIC_API_KEY is not set")
    uploads = await _collect_uploads(files, ssl, conn)
    analysis = await run_in_threadpool(_run_pipeline, uploads, mode, model or CLASSIFIER_MODEL)
    log.info(
        "analysis %s: files=%d events=%d clusters=%d mode=%s severities=%s in %dms",
        analysis["analysis_id"], len(uploads), analysis["event_count"], analysis["cluster_count"],
        analysis["classifier"]["mode"], analysis["summary"]["severity_breakdown"], analysis["duration_ms"],
    )
    return analysis


@app.get("/analyses", response_model=list[AnalysisSummary], dependencies=[Depends(require_token)])
async def list_analyses(limit: int = Query(default=50, ge=1, le=500),
                        offset: int = Query(default=0, ge=0)) -> list[dict[str, Any]]:
    return await run_in_threadpool(store.list_analyses, limit, offset)


@app.get("/analyses/{analysis_id}", response_model=AnalysisResponse, dependencies=[Depends(require_token)])
async def get_analysis(analysis_id: str) -> dict[str, Any]:
    analysis = await run_in_threadpool(store.get_analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="analysis not found")
    return analysis


@app.get("/analyses/{analysis_id}/findings.csv", dependencies=[Depends(require_token)])
async def get_analysis_csv(analysis_id: str) -> PlainTextResponse:
    analysis = await run_in_threadpool(store.get_analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="analysis not found")
    return PlainTextResponse(findings_to_csv(analysis), media_type="text/csv")


@app.get("/findings", response_model=list[Finding], dependencies=[Depends(require_token)])
async def query_findings(
    host: str | None = Query(default=None, max_length=64),
    severity: Literal["low", "medium", "high", "critical"] | None = None,
    min_severity: Literal["low", "medium", "high", "critical"] | None = None,
    service_id: str | None = Query(default=None, max_length=32),
    min_confidence: float | None = Query(default=None, ge=0.0, le=1.0),
    since: str | None = Query(default=None, max_length=40, description="ISO-8601 lower bound on analysis time"),
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[dict[str, Any]]:
    return await run_in_threadpool(
        store.query_findings, host, severity, min_severity, service_id, min_confidence, since, limit,
    )
