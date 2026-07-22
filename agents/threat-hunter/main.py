"""
Threat Hunter Agent — port 8002

Accepts POST /analyze with a query and a list of extracted IOCs, queries
S3 for matching events, and uses the configured LLM to synthesize
threat intelligence with a confidence score.

Security: query is sanitized before being sent to LLM. Internal IPs
are redacted from LLM context; only public IOCs are included.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

# Make agents/shared importable regardless of working directory
_SHARED = str(Path(__file__).resolve().parents[2] / "shared")
if _SHARED not in sys.path:
    sys.path.insert(0, _SHARED)

from llm_client import llm_complete, get_last_llm_metrics  # noqa: E402
from telemetry import init_telemetry, get_tracer, get_meter, instrument_fastapi_app  # noqa: E402
from s3_tools import (  # noqa: E402
    enrich_ip,
    investigate_ip,
    query_dns,
    query_flows,
    query_log_type,
    search_events,
)

# Initialize OTel tracing + metrics
init_telemetry(service_name="bhnocgentic-threat-hunter")

_meter = get_meter()
_request_counter  = _meter.create_counter("bhnoc.threat_hunter.requests", description="Total threat-hunter requests")
_request_duration = _meter.create_histogram("bhnoc.threat_hunter.duration_ms", unit="ms", description="Threat-hunter request latency")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("threat-hunter")

# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------

_RE_INTERNAL_IP  = re.compile(
    r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"
)
_RE_SECRET_TOKEN = re.compile(r"\b[A-Za-z0-9+/]{40,}\b")
_RE_PASSWORD     = re.compile(r"(?i)password\s*[:=]\s*\S+")
_RE_API_KEY_PAT  = re.compile(r"(?i)api[_-]?key\s*[:=]\s*\S+")

_RE_IP           = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_DOMAIN       = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
_RE_MD5          = re.compile(r"\b[0-9a-fA-F]{32}\b")
_RE_SHA256       = re.compile(r"\b[0-9a-fA-F]{64}\b")


def sanitize(text: str) -> str:
    text = _RE_INTERNAL_IP.sub("[INTERNAL-IP]", text)
    text = _RE_SECRET_TOKEN.sub("[REDACTED-SECRET]", text)
    text = _RE_PASSWORD.sub("password: [REDACTED]", text)
    text = _RE_API_KEY_PAT.sub("api_key: [REDACTED]", text)
    return text[:8000]


def is_public_ip(ip: str) -> bool:
    """Return True if IP is routable public (not RFC1918/loopback/link-local)."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a = int(parts[0])
        b = int(parts[1])
    except ValueError:
        return False
    if a == 10:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 127:
        return False
    if a == 169 and b == 254:
        return False
    return True


# ---------------------------------------------------------------------------
# IOC classification helpers
# ---------------------------------------------------------------------------

def classify_iocs(iocs: list[str]) -> dict[str, list[str]]:
    """Classify IOCs into types. Accepts both public AND private IPs —
    at Black Hat, internal IPs (10.220.x.x) are the hosts we're investigating."""
    classified: dict[str, list[str]] = {"ips": [], "domains": [], "md5s": [], "sha256s": []}
    for ioc in iocs:
        if _RE_MD5.fullmatch(ioc):
            classified["md5s"].append(ioc)
        elif _RE_SHA256.fullmatch(ioc):
            classified["sha256s"].append(ioc)
        elif _RE_IP.fullmatch(ioc):
            # Accept all valid IPs — internal IPs are conference attendee hosts
            parts = ioc.split(".")
            if all(0 <= int(p) <= 255 for p in parts):
                classified["ips"].append(ioc)
        elif _RE_DOMAIN.search(ioc):
            classified["domains"].append(ioc)
    return classified


# ---------------------------------------------------------------------------
# S3 data gathering
# ---------------------------------------------------------------------------

async def gather_threat_context(iocs: list[str], query: str) -> dict[str, Any]:
    """Query S3 for all relevant IOC data using uid-based session correlation.

    Corelight core concepts:
    - conn is central: all network connections logged here
    - uid links related logs across sourcetypes (same uid = same network session)
    - fuid links file-related events across sourcetypes
    - IP fields: id.orig_h=source, id.resp_h=dest, id.orig_p=src port, id.resp_p=dst port
    """
    classified = classify_iocs(iocs)
    ctx: dict[str, Any] = {
        "ioc_counts": {k: len(v) for k, v in classified.items()},
        "ip_investigations": [],
        "dns_hits": [],
        "search_hits": [],
    }
    time_range = {"hours": 48}

    # Deep IP investigation with uid correlation (conn → dns, http, ssl, files, alerts)
    for ip in classified["ips"][:3]:
        try:
            investigation = await investigate_ip(ip, time_range=time_range)
            ctx["ip_investigations"].append(investigation)
        except Exception as exc:
            logger.warning("investigate_ip(%s) failed: %s", ip, exc)

    # Domain lookups via DNS logs
    for domain in classified["domains"][:3]:
        try:
            hits = await query_dns(domain=domain, client_ip=None, time_range=time_range)
            ctx["dns_hits"].extend(hits[:10])
        except Exception as exc:
            logger.warning("query_dns(%s) failed: %s", domain, exc)

    # Hash lookups via files log
    if classified["md5s"] or classified["sha256s"]:
        try:
            file_events = await query_log_type("files", time_range=time_range, max_events=100)
            for fe in file_events:
                if fe.get("md5") in classified["md5s"] or fe.get("sha256") in classified["sha256s"]:
                    ctx.setdefault("file_hits", []).append(fe)
        except Exception as exc:
            logger.warning("files hash lookup failed: %s", exc)

    # Fallback: keyword search when no specific IOCs provided
    if not classified["ips"] and not classified["domains"] and not classified["md5s"]:
        keywords = [w for w in query.split() if len(w) > 4 and w.isalpha()][:5]
        if keywords:
            search_q = " OR ".join(keywords)
            for idx in ["corelight-events", "alerts"]:
                try:
                    hits = await search_events(search_q, idx, time_range)
                    ctx["search_hits"].extend(hits[:10])
                except Exception as exc:
                    logger.warning("search_events(%s) failed: %s", idx, exc)

    return ctx


# ---------------------------------------------------------------------------
# LLM analysis
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = (
    "You are a SOC threat analyst at Black Hat Asia 2026. You work from Corelight/Zeek "
    "telemetry (conn, dns, http, ssl, files, suricata) linked by uid.\n\n"
    "STYLE — FOLLOW EXACTLY:\n"
    "- Active voice, imperative. No hedging, no filler.\n"
    "- Skip 'Based on', 'It appears', 'The data shows', 'I analyzed'.\n"
    "- Lead with the conclusion. Cite specifics inline: IP, port, uid, signature.\n"
    "- One line per bullet. No prose paraphrasing.\n\n"
    "FORMAT (use these three headers only):\n"
    "## Answer\n"
    "1–2 sentences, direct.\n\n"
    "## Evidence\n"
    "Bullets of concrete data — IP, port, uid, signature, count. One line each.\n\n"
    "## Next Steps\n"
    "Numbered imperatives: 'Block 1.2.3.4', 'Pivot on uid=ABC', 'Check DNS for host X'.\n\n"
    "End with: ```json\n{\"confidence\": 0.XX}\n```\n"
    "Only cite data present in the telemetry — never invent IPs, domains, hashes, or events. "
    "If data is empty, say so in one line and set confidence < 0.3."
)


async def llm_analyze(query: str, context: dict[str, Any]) -> tuple[str, float]:
    """Send sanitized context to the LLM and return (answer, confidence)."""
    context_str = json.dumps(context, default=str)[:6000]
    user_content = (
        f"**Analyst Query:** {sanitize(query)}\n\n"
        f"**Telemetry Context:**\n```json\n{context_str}\n```"
    )

    try:
        answer = await llm_complete(
            system_prompt=SYSTEM_PROMPT,
            user_content=user_content,
            max_tokens=4096,
            temperature=0.1,
            thinking_budget=0,
        )
    except RuntimeError as exc:
        return (
            f"LLM not configured. Context gathered: {json.dumps(context, default=str)[:500]}",
            0.3,
        )

    # Extract confidence from the JSON block
    confidence = 0.7
    m = re.search(r'```json\s*\{[^}]*"confidence"\s*:\s*([0-9.]+)[^}]*\}\s*```', answer)
    if m:
        try:
            confidence = max(0.0, min(1.0, float(m.group(1))))
        except ValueError:
            pass

    return answer, confidence


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="BHNOCgentic Threat Hunter", version="0.2.0")
instrument_fastapi_app(app)


class AnalyzeRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=5000)
    extracted_iocs: list[str] = Field(default_factory=list)


class AnalyzeResponse(BaseModel):
    answer:     str
    confidence: float
    agent_used: str = "threat-hunter"
    data:       Any = None


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    tracer = get_tracer()
    with tracer.start_as_current_span("threat_hunter.analyze") as span:
        span.set_attribute("query.length", len(req.query))
        span.set_attribute("query.text", req.query[:500])
        span.set_attribute("iocs.count", len(req.extracted_iocs))

        start = time.monotonic()
        logger.info("analyze query_len=%d iocs=%d", len(req.query), len(req.extracted_iocs))

        with tracer.start_as_current_span("threat_hunter.gather_context") as ctx_span:
            context = await gather_threat_context(req.extracted_iocs, req.query)
            ctx_span.set_attribute("context.ip_investigations", len(context.get("ip_investigations", [])))
            ctx_span.set_attribute("context.dns_hits", len(context.get("dns_hits", [])))
            ctx_span.set_attribute("context.search_hits", len(context.get("search_hits", [])))

        answer, confidence = await llm_analyze(req.query, context)

        elapsed = time.monotonic() - start
        elapsed_ms = round(elapsed * 1000, 1)
        span.set_attribute("response.confidence", confidence)
        span.set_attribute("response.elapsed_ms", elapsed_ms)
        span.set_attribute("response.length", len(answer))
        span.set_attribute("response.text", (answer or "")[:2000])
        _request_counter.add(1)
        _request_duration.record(elapsed_ms)
        logger.info("analyze done elapsed=%.2fs confidence=%.2f", elapsed, confidence)

        # Return slim summary to UI — full context was already sent to LLM
        llm_metrics = get_last_llm_metrics()
        # Build slim summary with investigation highlights
        ip_summaries = []
        for inv in context.get("ip_investigations", []):
            s = inv.get("summary", {})
            ip_summaries.append({
                "ip": inv.get("ip"),
                "connections": s.get("total_connections", 0),
                "unique_dests": s.get("unique_destinations", 0),
                "services": s.get("services", []),
                "networks": s.get("networks", []),
                "alerts": s.get("alert_count", 0),
                "dns_queries": s.get("dns_query_count", 0),
                "bytes_sent": s.get("bytes_sent", 0),
                "bytes_recv": s.get("bytes_recv", 0),
            })

        summary_data: dict[str, Any] = {
            "iocs_searched":     req.extracted_iocs,
            "ioc_counts":        context.get("ioc_counts", {}),
            "ip_summaries":      ip_summaries,
            "dns_hits":          len(context.get("dns_hits", [])),
            "file_hits":         len(context.get("file_hits", [])),
            "search_hits":       len(context.get("search_hits", [])),
            "llm_metrics":       llm_metrics,
        }

        return AnalyzeResponse(
            answer=answer,
            confidence=confidence,
            data=summary_data,
        )


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "agent": "threat-hunter"}


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002, log_level="info")
