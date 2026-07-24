#!/usr/bin/env python3
"""
trace-export.py — Extract a reviewable CSV from a BHNOCgentic span-archive backup.

One row per user query, reconstructed by grouping spans on trace_id:
  - orchestrator.query           → user query, final response, routing intent,
                                    agent used, client IP/session, timing, confidence
  - orchestrator.classify        → classifier intent, confidence, reasoning
  - athena_hunter.execute_sql_*  → every SQL query fired against Athena
  - *.llm_analyze                → LLM analysis metadata (agent/service)

Usage:
    python tools/trace-export.py                   # uses newest backup, writes CSV
    python tools/trace-export.py --backup PATH     # specific backup dir
    python tools/trace-export.py --out FILE.csv
    python tools/trace-export.py --format jsonl    # JSONL instead of CSV
    python tools/trace-export.py --only-filtered       # only rows that hit a filter
    python tools/trace-export.py --raw                 # skip redaction (unmasked export)

Sensitive fields (client IP, session, user agent, referer) plus internal IPs and
secrets in prompts, responses and SQL are redacted by default. Pass --raw when you
explicitly need an unmasked export.
"""

from __future__ import annotations

import argparse
import csv
import glob
import gzip
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKUPS_DIR = REPO_ROOT / "backups"


# ---------------------------------------------------------------------------
# Redaction. Same patterns the telemetry pipeline uses (kept inline so this
# tool has no import dependency on the agents package).
# ---------------------------------------------------------------------------
_RE_INTERNAL_IP = re.compile(
    r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"
)
_RE_SECRET_TOKEN = re.compile(r"\b[A-Za-z0-9+/]{40,}\b")
_RE_PASSWORD = re.compile(r"(?i)password\s*[:=]\s*\S+")
_RE_API_KEY = re.compile(r"(?i)api[_-]?key\s*[:=]\s*\S+")
_RE_BEARER = re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+")

# Free-text fields that may carry internal IPs or secrets.
_REDACT_TEXT_FIELDS = ("query", "response", "classify_reasoning")
# Identity fields masked wholesale, not pattern-scrubbed.
_MASK_FIELDS = ("client_ip", "client_session", "client_user_agent", "client_referer")


def redact_text(text):
    """Scrub internal IPs, secrets, passwords, API keys and bearer tokens."""
    if not isinstance(text, str) or not text:
        return text
    text = _RE_INTERNAL_IP.sub("[INTERNAL-IP]", text)
    text = _RE_SECRET_TOKEN.sub("[REDACTED-SECRET]", text)
    text = _RE_PASSWORD.sub("password: [REDACTED]", text)
    text = _RE_API_KEY.sub("api_key: [REDACTED]", text)
    text = _RE_BEARER.sub("bearer [REDACTED]", text)
    return text


def redact_row(row: dict) -> dict:
    """Return a copy of a trace row with sensitive fields redacted."""
    out = dict(row)
    for f in _MASK_FIELDS:
        if out.get(f):
            out[f] = "[REDACTED]"
    for f in _REDACT_TEXT_FIELDS:
        if out.get(f):
            out[f] = redact_text(out[f])
    scrubbed_sql = []
    for entry in out.get("sql_queries") or []:
        e = dict(entry)
        if e.get("sql"):
            e["sql"] = redact_text(str(e["sql"]))
        scrubbed_sql.append(e)
    out["sql_queries"] = scrubbed_sql
    return out


def newest_backup() -> Path | None:
    candidates = sorted(glob.glob(str(BACKUPS_DIR / "aing-trace-*")))
    return Path(candidates[-1]) if candidates else None


def iter_spans(backup: Path):
    """Yield every parsed span from every .jsonl.gz file under the backup dir."""
    for path in sorted(backup.rglob("*.jsonl.gz")):
        try:
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
        except Exception as exc:
            print(f"warn: could not read {path}: {exc}", file=sys.stderr)


def truncate(s: str | None, n: int = 4000) -> str:
    if not s:
        return ""
    s = str(s)
    return (s[: n - 1] + "…") if len(s) > n else s


def build_rows(backup: Path):
    """Aggregate spans into one row per trace_id."""
    by_trace: dict[str, dict] = defaultdict(lambda: {
        "sql_queries": [],
    })

    for span in iter_spans(backup):
        trace_id = span.get("trace_id")
        if not trace_id:
            continue
        row = by_trace[trace_id]
        attrs = span.get("attributes") or {}
        name = span.get("name", "")

        if name == "orchestrator.query":
            row.update({
                "trace_id":             trace_id,
                "timestamp":            span.get("start_time") or row.get("timestamp"),
                "duration_ms":          span.get("duration_ms"),
                "status":               span.get("status_code"),
                "job_id":               attrs.get("job.id"),
                "client_ip":            attrs.get("client.ip"),
                "client_session":       attrs.get("client.session_id"),
                "client_user_agent":    attrs.get("client.user_agent"),
                "client_referer":       attrs.get("client.referer"),
                "query":                attrs.get("query.text"),
                "query_length":         attrs.get("query.length"),
                "response":             attrs.get("response.text"),
                "response_length":      attrs.get("response.length"),
                "response_confidence":  attrs.get("response.confidence"),
                "response_elapsed_ms":  attrs.get("response.elapsed_ms"),
                "routing_intent":       attrs.get("routing.intent"),
                "agent_used":           attrs.get("agent.used"),
                "filter_restricted":    attrs.get("filter.restricted"),
                "filter_guardrail":     attrs.get("filter.guardrail"),
                "filter_kill_switch":   attrs.get("filter.kill_switch"),
            })
        elif name == "orchestrator.classify":
            row["classify_intent"]     = attrs.get("classification.intent")
            row["classify_confidence"] = attrs.get("classification.confidence")
            row["classify_reasoning"]  = attrs.get("classification.reasoning")
        elif name.startswith("athena_hunter.execute_sql_") or (
            name.startswith("POST /") is False and "sql.query" in attrs
        ):
            sql = attrs.get("sql.query")
            if sql:
                row["sql_queries"].append({
                    "sql":             str(sql),
                    "row_count":       attrs.get("sql.row_count"),
                    "execution_ms":    attrs.get("sql.execution_time_ms"),
                    "data_scanned_mb": attrs.get("sql.data_scanned_mb"),
                })
        elif name == "athena_hunter.gather_context":
            row["athena_total_rows"]    = attrs.get("context.total_rows")
            row["athena_total_queries"] = attrs.get("context.total_queries")

    # Only keep traces we could identify as user-originated queries
    return [
        r for r in by_trace.values()
        if r.get("trace_id") and r.get("query") is not None
    ]


CSV_COLUMNS = [
    "timestamp", "trace_id", "job_id",
    "client_ip", "client_session", "client_user_agent",
    "routing_intent", "agent_used",
    "classify_intent", "classify_confidence", "classify_reasoning",
    "query",
    "response", "response_confidence", "response_length",
    "response_elapsed_ms", "duration_ms",
    "filter_restricted", "filter_guardrail", "filter_kill_switch",
    "sql_count", "sql_queries",
    "athena_total_rows", "athena_total_queries",
    "status",
]


def to_csv_row(row: dict) -> dict:
    sqls = row.get("sql_queries") or []
    out = {k: row.get(k, "") for k in CSV_COLUMNS if k not in ("sql_queries", "sql_count")}
    out["sql_count"] = len(sqls)
    # Inline SQL text, one per line, truncated per-entry
    out["sql_queries"] = "\n\n---\n\n".join(truncate(s["sql"], 1200) for s in sqls)
    out["query"] = truncate(out.get("query") or "", 4000)
    out["response"] = truncate(out.get("response") or "", 4000)
    # Normalise bools
    for b in ("filter_restricted", "filter_guardrail", "filter_kill_switch"):
        v = out.get(b)
        out[b] = "true" if v in (True, "True", "true", 1, "1") else ("false" if v is not None and v != "" else "")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--backup", type=Path, help="backup dir (default: newest under backups/)")
    ap.add_argument("--out", type=Path, help="output file (default: trace-export-<ts>.<ext>)")
    ap.add_argument("--format", choices=["csv", "jsonl"], default="csv")
    ap.add_argument("--only-filtered", action="store_true",
                    help="only emit rows where a filter/guardrail/kill-switch fired")
    ap.add_argument("--session", type=str, default=None,
                    help="filter to a specific client session id (prefix match OK)")
    ap.add_argument("--by-session", action="store_true",
                    help="print a per-session summary to stderr then write the CSV")
    ap.add_argument("--raw", action="store_true",
                    help="skip redaction and export unmasked fields (default: redacted)")
    args = ap.parse_args()

    backup = args.backup or newest_backup()
    if not backup or not backup.exists():
        print("error: no backup found. Pass --backup PATH or create one with the usual rsync flow.",
              file=sys.stderr)
        return 2

    print(f"reading backup: {backup}", file=sys.stderr)
    rows = build_rows(backup)
    print(f"extracted {len(rows)} user-query traces", file=sys.stderr)

    if args.only_filtered:
        rows = [r for r in rows if any(r.get(k) for k in
                ("filter_restricted", "filter_guardrail", "filter_kill_switch"))]
        print(f"filtered to {len(rows)} rows where a guard fired", file=sys.stderr)

    if args.session:
        want = args.session
        rows = [r for r in rows if r.get("client_session") and str(r["client_session"]).startswith(want)]
        print(f"filtered to {len(rows)} rows for session prefix '{want}'", file=sys.stderr)

    # Sort chronologically
    rows.sort(key=lambda r: r.get("timestamp") or "")

    if args.by_session:
        from collections import defaultdict
        buckets: dict[str, list[dict]] = defaultdict(list)
        no_sid = 0
        for r in rows:
            sid = r.get("client_session") or ""
            if sid:
                buckets[sid].append(r)
            else:
                no_sid += 1
        print(f"\n=== per-session summary ({len(buckets)} sessions, {no_sid} rows without session) ===",
              file=sys.stderr)
        session_summaries = sorted(
            buckets.items(),
            key=lambda kv: (len(kv[1]), kv[0]),
            reverse=True,
        )
        for sid, sess_rows in session_summaries:
            ips = sorted({r["client_ip"] for r in sess_rows if r.get("client_ip")})
            first_ts = sess_rows[0].get("timestamp") or ""
            last_ts = sess_rows[-1].get("timestamp") or ""
            intents = sorted({str(r.get("routing_intent") or "") for r in sess_rows if r.get("routing_intent")})
            print(
                f"  {sid[:12]}…  queries={len(sess_rows):3d}  "
                f"ip={','.join(ips):20s}  {first_ts[:19]} → {last_ts[:19]}  "
                f"intents={','.join(intents) or '-'}",
                file=sys.stderr,
            )

    # Redacted by default. The per-session summary above ran on raw rows (operator
    # console only); the written export is masked unless --raw was passed.
    if args.raw:
        print("warning: --raw set, export will contain UNREDACTED IPs/sessions/prompts",
              file=sys.stderr)
    else:
        rows = [redact_row(r) for r in rows]

    if args.out is None:
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        ext = "csv" if args.format == "csv" else "jsonl"
        args.out = REPO_ROOT / f"trace-export-{ts}.{ext}"

    args.out.parent.mkdir(parents=True, exist_ok=True)

    if args.format == "csv":
        with args.out.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow(to_csv_row(r))
    else:
        with args.out.open("w", encoding="utf-8") as fh:
            for r in rows:
                # JSONL keeps the full SQL list as an array for downstream analysis
                out = dict(r)
                fh.write(json.dumps(out, default=str, ensure_ascii=False) + "\n")

    print(f"wrote {args.out}  ({args.out.stat().st_size / 1024:.1f} KB)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
