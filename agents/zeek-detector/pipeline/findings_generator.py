"""
Findings generator: classified clusters -> SOC findings with evidence chains.

Vendored from research-pipeline `findings_generator.py` (APE-86). Changes:

  * File-writing and stdout helpers dropped; the service returns and stores the
    report itself. `findings_to_csv` renders the CISO summary to a string.
  * Each finding carries `classifier_mode` (rules / llm / rules-fallback) so an
    analyst can tell a deterministic label from a model's.
  * The research-only `acceptance_criteria` block is gone from the summary; it
    hard-coded "classified with Claude" as True regardless of mode.
  * Duplicate top-level `session_duration_seconds` removed (it lives in `timeline`).
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

_log = logging.getLogger("zeek-detector.playbooks")

# How many hunt playbooks one finding links to, most relevant first. Same cap
# as packages/web-server/src/services/huntCatalog.ts MAX_LINKED_PLAYBOOKS.
MAX_LINKED_PLAYBOOKS = 4
PLAYBOOK_MAP_FILENAME = "finding-playbook-map.json"

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}

CSV_FIELDS = [
    "finding_id", "severity", "host", "destination", "service_name",
    "behavior_classification", "confidence", "confidence_level", "classifier_mode",
    "first_seen", "session_duration_seconds", "request_count", "detected_patterns",
    "playbooks", "narrative", "recommendation",
]

_EMPTY_MAP: dict = {"patterns": {}, "behaviors": {}}
_playbook_map: dict | None = None


def _playbook_map_candidates() -> list[Path]:
    """ZEEK_PLAYBOOK_MAP is exclusive when set; otherwise the container copy
    (next to main.py) and then the repo checkout (threathunt-catalog/)."""
    env = os.environ.get("ZEEK_PLAYBOOK_MAP")
    if env:
        return [Path(env)]
    here = Path(__file__).resolve()
    return [
        here.parents[1] / PLAYBOOK_MAP_FILENAME,
        here.parents[3] / "threathunt-catalog" / PLAYBOOK_MAP_FILENAME,
    ]


def load_playbook_map() -> dict:
    """The `zeek_detector` block of threathunt-catalog/finding-playbook-map.json.

    Read once per process. A missing or unreadable map is a warning and an
    empty mapping, never a failed upload: the finding is still the finding.
    """
    global _playbook_map
    if _playbook_map is not None:
        return _playbook_map
    for candidate in _playbook_map_candidates():
        try:
            data = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        block = data.get("zeek_detector") or {}
        _playbook_map = {
            "patterns": dict(block.get("patterns") or {}),
            "behaviors": dict(block.get("behaviors") or {}),
        }
        return _playbook_map
    _log.warning("%s not found; findings carry no playbook links", PLAYBOOK_MAP_FILENAME)
    _playbook_map = dict(_EMPTY_MAP)
    return _playbook_map


def playbooks_for(behavior: str, patterns: list[str]) -> list[str]:
    """Hunt playbook ids for one finding: patterns first (the specific
    evidence), then the behaviour label; deduped in order and capped."""
    m = load_playbook_map()
    ordered: list[str] = []
    for p in patterns:
        ordered.extend(m["patterns"].get(p, []))
    ordered.extend(m["behaviors"].get(behavior, []))
    out: list[str] = []
    for pb in ordered:
        if pb not in out:
            out.append(pb)
        if len(out) >= MAX_LINKED_PLAYBOOKS:
            break
    return out


def _ts_to_iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _narrative_summary(finding: dict) -> str:
    """Human-readable one-liner for a finding (CISO-friendly)."""
    host = finding["host"]
    service = finding["service_name"]
    behavior = finding["behavior_classification"]
    confidence = finding["confidence"]
    duration = finding["timeline"].get("session_duration_seconds")
    severity = finding["severity"]
    patterns = finding.get("detected_patterns", [])

    if "context_reset" in patterns and "agentic_loop" in patterns:
        pattern_str = "exhibiting context-window resets and tight agentic loop timing"
    elif "context_reset" in patterns:
        pattern_str = "exhibiting context-window reset patterns"
    elif "agentic_loop" in patterns:
        pattern_str = "exhibiting tight agentic loop timing"
    else:
        pattern_str = "making API-style requests"

    duration_str = f" over a {duration:.0f}-second session" if duration else ""
    return (
        f"Host {host} was observed connecting to {service} {pattern_str}"
        f"{duration_str}, consistent with {behavior} "
        f"({confidence:.0%} confidence, severity: {severity})."
    )


def generate_findings(
    classifications: list[dict],
    cluster_reports: list[dict] | None = None,
    events: list[dict] | None = None,
    classifier_label: str = "rules",
) -> dict:
    """Convert classifications into {"metadata", "summary", "findings"}."""
    metrics_lookup: dict[tuple, dict] = {}
    for cr in cluster_reports or []:
        metrics_lookup[(cr.get("src_host"), cr.get("dst_host"), cr.get("dst_port"))] = cr

    ts_lookup: dict[tuple, tuple[float, float]] = {}
    for ev in events or []:
        key = (ev.get("src_host"), ev.get("dst_host"), ev.get("dst_port"))
        ts = ev.get("ts")
        if ts is None:
            continue
        if key not in ts_lookup:
            ts_lookup[key] = (ts, ts)
        else:
            lo, hi = ts_lookup[key]
            ts_lookup[key] = (min(lo, ts), max(hi, ts))

    findings: list[dict] = []
    ai_services_found: set[str] = set()
    hosts_involved: set[str] = set()

    for cls in classifications:
        src = cls.get("src_host", "unknown")
        dst = cls.get("dst_host", "unknown")
        port = cls.get("dst_port", 443)
        key = (src, dst, port)

        service_id = cls.get("service_id", "unknown")
        service_name = cls.get("service_name", "Unknown Service")
        patterns = cls.get("detected_patterns", cls.get("patterns", []))
        request_count = cls.get("request_count", 0)
        server_names = cls.get("server_names", [])

        cluster_metrics = metrics_lookup.get(key, {})
        session_duration = cluster_metrics.get("session_duration")
        mean_iat = cluster_metrics.get("mean_iat")
        timing_entropy = cluster_metrics.get("timing_entropy")
        sawtooth_score = cluster_metrics.get("sawtooth_score", 0.0)
        loop_score = cluster_metrics.get("loop_score", 0.0)

        ts_range = ts_lookup.get(key)
        first_ts = _ts_to_iso(ts_range[0]) if ts_range else None
        last_ts = _ts_to_iso(ts_range[1]) if ts_range else None

        evidence_chain = list(cls.get("evidence", []))
        if server_names:
            evidence_chain.insert(0, f"SNI/server_name: {', '.join(server_names)}")
        if request_count:
            evidence_chain.append(f"{request_count} requests observed in session")
        if patterns:
            evidence_chain.append(f"Timing patterns detected: {', '.join(patterns)}")
        if sawtooth_score > 0:
            evidence_chain.append(f"Sawtooth score: {sawtooth_score:.4f} (context-window resets)")
        if loop_score > 0:
            evidence_chain.append(f"Loop score: {loop_score:.4f} (repetitive tool-call timing)")
        if timing_entropy is not None:
            evidence_chain.append(f"Timing entropy: {timing_entropy:.4f} bits")

        finding = {
            "finding_id": f"AI-{len(findings) + 1:04d}",
            "host": src,
            "destination": f"{dst}:{port}",
            "service_id": service_id,
            "service_name": service_name,
            "behavior_classification": cls.get("behavior_classification", "unknown"),
            "confidence": float(cls.get("confidence", 0.0)),
            "confidence_level": cls.get("confidence_level", "insufficient"),
            "severity": cls.get("severity", "low"),
            "classifier_mode": cls.get("classifier_mode", "rules"),
            "detected_patterns": list(patterns),
            "playbooks": playbooks_for(cls.get("behavior_classification", "unknown"), list(patterns)),
            "evidence_chain": evidence_chain,
            "timeline": {
                "first_seen": first_ts,
                "last_seen": last_ts,
                "session_duration_seconds": round(session_duration, 2) if session_duration else None,
            },
            "metrics": {
                "request_count": request_count,
                "mean_inter_request_seconds": round(mean_iat, 4) if mean_iat else None,
                "timing_entropy_bits": round(timing_entropy, 4) if timing_entropy else None,
                "sawtooth_score": sawtooth_score,
                "loop_score": loop_score,
            },
            "server_names": list(server_names),
            "recommendation": cls.get("recommendation", "Monitor traffic for further activity."),
            "narrative": None,
        }
        finding["narrative"] = _narrative_summary(finding)

        if service_id != "unknown":
            ai_services_found.add(service_name)
        hosts_involved.add(src)
        findings.append(finding)

    findings.sort(key=lambda f: (-SEVERITY_ORDER.get(f["severity"], 0), -f["confidence"]))
    # Re-number after the sort so AI-0001 is the top finding.
    for i, f in enumerate(findings, start=1):
        f["finding_id"] = f"AI-{i:04d}"

    summary = {
        "total_clusters_analyzed": len(findings),
        "ai_service_clusters": sum(1 for f in findings if f["service_id"] != "unknown"),
        "high_confidence_findings": sum(1 for f in findings if f["confidence"] >= 0.85),
        "agentic_orchestration_findings": sum(
            1 for f in findings if f["behavior_classification"] == "agentic-orchestration"
        ),
        "unique_ai_services_identified": sorted(ai_services_found),
        "hosts_involved": sorted(hosts_involved),
        "severity_breakdown": {
            sev: sum(1 for f in findings if f["severity"] == sev)
            for sev in ["critical", "high", "medium", "low"]
        },
        "classifier_modes": {
            mode: sum(1 for f in findings if f["classifier_mode"] == mode)
            for mode in sorted({f["classifier_mode"] for f in findings})
        },
    }

    metadata = {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "pipeline_stage": "zeek_ai_detection",
        "classifier": classifier_label,
        "version": "1.0.0",
    }

    return {"metadata": metadata, "summary": summary, "findings": findings}


def findings_to_csv(findings_report: dict) -> str:
    """CISO-friendly CSV summary of a findings report."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for finding in findings_report.get("findings", []):
        timeline = finding.get("timeline") or {}
        writer.writerow({
            **finding,
            "first_seen": timeline.get("first_seen", ""),
            "session_duration_seconds": timeline.get("session_duration_seconds", ""),
            "request_count": (finding.get("metrics") or {}).get("request_count", ""),
            "detected_patterns": "|".join(finding.get("detected_patterns", [])),
            "playbooks": "|".join(finding.get("playbooks", [])),
        })
    return buf.getvalue()
