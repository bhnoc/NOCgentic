"""
s3_tools.py — Async helper functions for querying Corelight/Zeek security
event data from S3.

Data is stored as gzipped Zeek TSV log files under:
    s3://{bucket}/bh-asia-26/corelight/{YYYY-MM-DD}/{logtype}_{timestamp}.log.gz

Each file has a Zeek header block (#separator, #fields, #types, etc.)
followed by tab-separated data rows.

Environment variables:
    S3_BUCKET         — Bucket name (required)
    S3_REGION         — Bucket region (default: us-west-2)
    S3_PREFIX         — Top-level prefix (default: "bh-asia-26")
"""

from __future__ import annotations

import gzip
import io
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

S3_BUCKET: str = os.getenv("S3_BUCKET", "")
S3_REGION: str = os.getenv("S3_REGION", "us-west-2")
S3_PREFIX: str = os.getenv("S3_PREFIX", "bh-asia-26").strip("/")

def _get_s3():
    """Return a fresh boto3 S3 client on every call.

    Do NOT cache — see athena_client._get_athena() for rationale:
    cached clients hold stale instance-role credentials after IMDS
    rotation (~6 h) and start throwing "expired token" errors.
    """
    session_kwargs: dict[str, str] = {}
    profile = os.getenv("AWS_PROFILE")
    if profile:
        session_kwargs["profile_name"] = profile
    session = boto3.Session(region_name=S3_REGION, **session_kwargs)
    return session.client("s3")


# ---------------------------------------------------------------------------
# Zeek TSV parser
# ---------------------------------------------------------------------------

def _parse_zeek_tsv(raw_bytes: bytes) -> tuple[list[str], list[dict]]:
    """Parse a gzipped Zeek TSV log file into a list of dicts.

    Returns (field_names, records).
    """
    try:
        text = gzip.decompress(raw_bytes).decode("utf-8", errors="replace")
    except gzip.BadGzipFile:
        text = raw_bytes.decode("utf-8", errors="replace")

    fields: list[str] = []
    separator = "\t"
    unset = "-"
    empty = "(empty)"
    records: list[dict] = []

    for line in text.splitlines():
        if line.startswith("#separator"):
            # e.g. #separator \x09
            sep_val = line.split(" ", 1)[1] if " " in line else "\t"
            separator = sep_val.replace("\\x09", "\t")
        elif line.startswith("#set_separator"):
            pass
        elif line.startswith("#empty_field"):
            parts = line.split(separator, 1)
            if len(parts) > 1:
                empty = parts[1]
        elif line.startswith("#unset_field"):
            parts = line.split(separator, 1)
            if len(parts) > 1:
                unset = parts[1]
        elif line.startswith("#fields"):
            fields = line.split(separator)[1:]
        elif line.startswith("#"):
            continue
        elif fields and line:
            vals = line.split(separator)
            record: dict[str, Any] = {}
            for i, fname in enumerate(fields):
                if i < len(vals):
                    v = vals[i]
                    if v == unset or v == empty:
                        record[fname] = None
                    else:
                        record[fname] = _coerce_value(fname, v)
                else:
                    record[fname] = None
            records.append(record)

    return fields, records


def _coerce_value(field: str, value: str) -> Any:
    """Best-effort type coercion for Zeek field values."""
    # Timestamps — Zeek uses unix epoch float
    if field == "ts":
        try:
            return float(value)
        except ValueError:
            return value

    # Port numbers
    if field in ("id.orig_p", "id.resp_p", "id.vlan", "id.vlan_inner",
                 "trans_id", "status_code", "dst_port", "src_port"):
        try:
            return int(value)
        except ValueError:
            return value

    # Numeric fields
    if field in ("duration", "orig_bytes", "resp_bytes", "missed_bytes",
                 "orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes",
                 "request_body_len", "response_body_len", "rtt",
                 "confidence", "alert.severity", "auth_attempts"):
        try:
            if "." in value:
                return float(value)
            return int(value)
        except ValueError:
            return value

    # Boolean
    if field in ("auth_success", "local_orig", "local_resp", "AA", "TC",
                 "RD", "RA", "rejected", "resumed", "established",
                 "is_trusted_domain"):
        return value == "T"

    # Set/vector fields (comma-separated)
    if "," in value and field in ("answers", "TTLs", "cert_chain_fps",
                                   "tunnel_parents", "tags"):
        return value.split(",")

    return value


def _ts_to_datetime(ts: Any) -> datetime | None:
    """Convert Zeek epoch timestamp to datetime."""
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        return None


# ---------------------------------------------------------------------------
# S3 data loading — reads Zeek TSV .log.gz files
# ---------------------------------------------------------------------------

def _list_log_files(
    log_type: str,
    date_str: str | None = None,
    max_files: int = 10,
) -> list[str]:
    """List S3 keys for a given Zeek log type on a specific date."""
    if not S3_BUCKET:
        return []

    s3 = _get_s3()

    # Default to today and yesterday for coverage
    if date_str is None:
        now = datetime.now(timezone.utc)
        dates = [
            now.strftime("%Y-%m-%d"),
            (now - timedelta(days=1)).strftime("%Y-%m-%d"),
        ]
    else:
        dates = [date_str]

    keys: list[str] = []
    for d in dates:
        prefix = f"{S3_PREFIX}/corelight/{d}/{log_type}_"
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=S3_BUCKET, Prefix=prefix):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    if key.endswith(".log.gz"):
                        keys.append(key)
                    if len(keys) >= max_files:
                        break
                if len(keys) >= max_files:
                    break
        except Exception as exc:
            logger.warning("S3 list failed for prefix=%s: %s", prefix, exc)

        if len(keys) >= max_files:
            break

    # Most recent files first (filename contains timestamp)
    keys.sort(reverse=True)
    return keys[:max_files]


def _parse_zeek_grep(raw_bytes: bytes, grep_pattern: str) -> tuple[list[str], list[dict]]:
    """Parse a gzipped Zeek TSV file, only returning rows matching grep_pattern.

    Searches the raw tab-separated lines for the pattern BEFORE parsing into
    dicts, which is dramatically faster than parsing all records and filtering.
    """
    try:
        text = gzip.decompress(raw_bytes).decode("utf-8", errors="replace")
    except gzip.BadGzipFile:
        text = raw_bytes.decode("utf-8", errors="replace")

    fields: list[str] = []
    separator = "\t"
    unset = "-"
    empty = "(empty)"
    records: list[dict] = []

    for line in text.splitlines():
        if line.startswith("#separator"):
            sep_val = line.split(" ", 1)[1] if " " in line else "\t"
            separator = sep_val.replace("\\x09", "\t")
        elif line.startswith("#empty_field"):
            parts = line.split(separator, 1)
            if len(parts) > 1:
                empty = parts[1]
        elif line.startswith("#unset_field"):
            parts = line.split(separator, 1)
            if len(parts) > 1:
                unset = parts[1]
        elif line.startswith("#fields"):
            fields = line.split(separator)[1:]
        elif line.startswith("#"):
            continue
        elif fields and line:
            # Fast check: does the raw line contain the pattern?
            if grep_pattern not in line:
                continue
            vals = line.split(separator)
            record: dict[str, Any] = {}
            for i, fname in enumerate(fields):
                if i < len(vals):
                    v = vals[i]
                    if v == unset or v == empty:
                        record[fname] = None
                    else:
                        record[fname] = _coerce_value(fname, v)
                else:
                    record[fname] = None
            records.append(record)

    return fields, records


def _load_zeek_events(
    log_type: str,
    max_files: int = 10,
    max_events: int = 500,
    date_str: str | None = None,
    grep_pattern: str | None = None,
) -> list[dict]:
    """Load and parse Zeek events from S3 for a given log type.

    If grep_pattern is provided, only rows containing that string in the raw
    TSV line are parsed. This is extremely efficient — the pattern check happens
    on the raw text before any dict construction, so scanning 30 files for one
    IP is fast.
    """
    keys = _list_log_files(log_type, date_str=date_str, max_files=max_files)
    if not keys:
        logger.info("No files found for log_type=%s", log_type)
        return []

    s3 = _get_s3()
    all_events: list[dict] = []

    for key in keys:
        if len(all_events) >= max_events:
            break
        try:
            resp = s3.get_object(Bucket=S3_BUCKET, Key=key)
            raw = resp["Body"].read()
            if grep_pattern:
                _, records = _parse_zeek_grep(raw, grep_pattern)
            else:
                _, records = _parse_zeek_tsv(raw)
            for rec in records:
                rec["_s3_key"] = key
                rec["_log_type"] = log_type
                all_events.append(rec)
                if len(all_events) >= max_events:
                    break
        except Exception as exc:
            logger.warning("Failed to read s3://%s/%s: %s", S3_BUCKET, key, exc)

    logger.info("Loaded %d %s events from %d files (grep=%s)",
                len(all_events), log_type, len(keys), grep_pattern or "none")
    return all_events


# ---------------------------------------------------------------------------
# Time filtering
# ---------------------------------------------------------------------------

def _filter_by_time(events: list[dict], hours: int = 24) -> list[dict]:
    """Filter events to those within the last N hours based on Zeek `ts` field.

    Falls back to returning all events if time filtering excludes everything.
    """
    if not events:
        return events

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    cutoff_epoch = cutoff.timestamp()

    filtered = []
    for evt in events:
        ts = evt.get("ts")
        if ts is None:
            filtered.append(evt)
            continue
        try:
            if float(ts) >= cutoff_epoch:
                filtered.append(evt)
        except (TypeError, ValueError):
            filtered.append(evt)

    if len(filtered) == 0 and len(events) > 0:
        logger.warning(
            "Time filter (%dh) excluded all %d events — returning all data.",
            hours, len(events),
        )
        return events

    logger.info("Time filter: %d/%d events within last %dh", len(filtered), len(events), hours)
    return filtered


# ---------------------------------------------------------------------------
# Field-based filtering
# ---------------------------------------------------------------------------

def _match_filters(events: list[dict], filters: dict[str, Any]) -> list[dict]:
    """Filter events by key=value matching (case-insensitive)."""
    if not filters:
        return events
    results = []
    for evt in events:
        match = True
        for k, v in filters.items():
            evt_val = evt.get(k)
            if evt_val is None:
                match = False
                break
            if str(evt_val).lower() != str(v).lower():
                match = False
                break
        if match:
            results.append(evt)
    return results


def _slim_event(evt: dict, keep_fields: list[str] | None = None) -> dict:
    """Strip internal/low-value fields for a slimmer response."""
    skip = {"_s3_key", "_log_type", "spcap.url", "spcap.rule", "spcap.trigger",
            "payload", "packet", "payload_printable",
            "client_headers", "server_headers",
            "ja3_string_", "ja3_string_client_ciphers", "ja3_string_extensions",
            "ja3_string_extensions_sum", "ja3_string_e_curves", "ja3_string_ec_point_fmt",
            "ja3s_string_", "ja3s_string_version", "ja3s_string_server_extensions",
            "ja3s_string_cipher"}
    if keep_fields:
        return {k: v for k, v in evt.items() if k in keep_fields and v is not None}
    return {k: v for k, v in evt.items() if k not in skip and v is not None}


def _format_ts(evt: dict) -> dict:
    """Add a human-readable timestamp field if ts is epoch."""
    ts = evt.get("ts")
    if ts is not None:
        dt = _ts_to_datetime(ts)
        if dt:
            evt["_time"] = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    return evt


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def query_alerts(
    filters: dict[str, Any],
    time_range: dict[str, Any],
) -> list[dict]:
    """Search Suricata IDS alerts from Corelight data."""
    hours = int(time_range.get("hours", 24))
    events = _load_zeek_events("suricata_corelight", max_files=15, max_events=300)
    events = _filter_by_time(events, hours=hours)

    # Map generic filter names to Zeek field names
    zeek_filters: dict[str, Any] = {}
    if filters.get("severity"):
        zeek_filters["alert.severity"] = filters["severity"]
    if filters.get("action"):
        zeek_filters["alert.action"] = filters["action"]
    if filters.get("src_ip"):
        zeek_filters["id.orig_h"] = filters["src_ip"]
    if filters.get("dst_ip"):
        zeek_filters["id.resp_h"] = filters["dst_ip"]

    if zeek_filters:
        events = _match_filters(events, zeek_filters)

    # Keyword filtering on alert.signature and alert.category
    if filters.get("threat_category"):
        cat = filters["threat_category"].lower()
        events = [e for e in events
                  if cat in str(e.get("alert.category", "")).lower()
                  or cat in str(e.get("alert.signature", "")).lower()]

    # Add readable timestamps and slim down
    events = [_format_ts(_slim_event(e)) for e in events]
    events.sort(key=lambda e: e.get("ts", 0), reverse=True)
    return events[:50]


async def query_flows(
    src_ip: str | None,
    dst_ip: str | None,
    port: int | None,
    time_range: dict[str, Any],
) -> list[dict]:
    """Search network connection (conn) logs from Corelight."""
    hours = int(time_range.get("hours", 24))
    # Use grep_pattern for targeted IP search across more files
    grep = src_ip or dst_ip
    max_f = 25 if grep else 15
    events = _load_zeek_events("conn", max_files=max_f, max_events=500, grep_pattern=grep)
    events = _filter_by_time(events, hours=hours)

    if src_ip:
        events = [e for e in events if e.get("id.orig_h") == src_ip]
    if dst_ip:
        events = [e for e in events if e.get("id.resp_h") == dst_ip]
    if port is not None:
        events = [e for e in events
                  if e.get("id.resp_p") == port or e.get("id.orig_p") == port]

    conn_fields = [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "proto", "service", "duration", "orig_bytes", "resp_bytes",
        "conn_state", "missed_bytes", "history", "orig_pkts", "resp_pkts",
        "orig_ip_bytes", "resp_ip_bytes", "community_id",
        "id.orig_network_name", "id.resp_network_name",
        "id.orig_mac", "id.resp_mac",
        "remote_asn", "remote_organization", "remote_country",
    ]
    events = [_format_ts(_slim_event(e, keep_fields=conn_fields)) for e in events]
    events.sort(key=lambda e: e.get("ts", 0), reverse=True)
    return events[:50]


async def query_dns(
    domain: str | None,
    client_ip: str | None,
    time_range: dict[str, Any],
) -> list[dict]:
    """Search DNS query logs from Corelight."""
    hours = int(time_range.get("hours", 24))
    # Use grep_pattern for targeted search
    grep = client_ip or domain
    max_f = 25 if grep else 15
    events = _load_zeek_events("dns", max_files=max_f, max_events=500, grep_pattern=grep)
    events = _filter_by_time(events, hours=hours)

    if domain:
        domain_lower = domain.lower().replace("*", "")
        events = [e for e in events
                  if domain_lower in str(e.get("query", "")).lower()]
    if client_ip:
        events = [e for e in events if e.get("id.orig_h") == client_ip]

    dns_fields = [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "proto", "query", "qtype_name", "rcode_name", "answers", "TTLs",
        "AA", "TC", "RD", "RA", "rejected",
        "icann_domain", "icann_tld",
        "id.orig_network_name", "id.orig_network_ssid",
    ]
    events = [_format_ts(_slim_event(e, keep_fields=dns_fields)) for e in events]
    events.sort(key=lambda e: e.get("ts", 0), reverse=True)
    return events[:50]


async def enrich_ip(ip: str) -> dict[str, Any]:
    """Retrieve events for a given IP across conn, dns, ssl, suricata logs."""
    all_events: list[dict] = []

    for log_type in ["conn", "dns", "ssl", "suricata_corelight"]:
        events = _load_zeek_events(log_type, max_files=5, max_events=100)
        for evt in events:
            if ip in (evt.get("id.orig_h"), evt.get("id.resp_h")):
                all_events.append(_format_ts(_slim_event(evt)))

    return {
        "ip": ip,
        "total_events": len(all_events),
        "events": all_events[:30],
        "log_types": list({e.get("_log_type", "unknown") for e in all_events}),
        "summary": f"Found {len(all_events)} events for {ip} across Corelight logs.",
    }


async def get_top_talkers(
    time_range: dict[str, Any],
    limit: int = 10,
) -> list[dict]:
    """Return the top source IPs by connection volume from conn logs."""
    hours = int(time_range.get("hours", 24))
    events = _load_zeek_events("conn", max_files=10, max_events=500)
    events = _filter_by_time(events, hours=hours)

    counts: dict[str, dict[str, Any]] = {}
    for evt in events:
        src = evt.get("id.orig_h")
        if not src:
            continue
        if src not in counts:
            counts[src] = {
                "ip": src,
                "count": 0,
                "total_bytes": 0,
                "network": evt.get("id.orig_network_name"),
                "unique_dsts": set(),
            }
        counts[src]["count"] += 1
        counts[src]["total_bytes"] += (evt.get("orig_bytes") or 0) + (evt.get("resp_bytes") or 0)
        dst = evt.get("id.resp_h")
        if dst:
            counts[src]["unique_dsts"].add(dst)

    # Convert sets to counts for JSON serialization
    for entry in counts.values():
        entry["unique_dst_count"] = len(entry["unique_dsts"])
        del entry["unique_dsts"]

    sorted_talkers = sorted(counts.values(), key=lambda x: x["count"], reverse=True)
    return sorted_talkers[:limit]


async def search_events(
    query: str,
    index: str,
    time_range: dict[str, Any],
) -> list[dict]:
    """Freeform text search across Zeek log types."""
    # Map index names to Zeek log types
    type_map = {
        "corelight-events": ["conn", "dns", "http", "ssl"],
        "paloalto-events": ["suricata_corelight"],
        "alerts": ["suricata_corelight", "notice"],
        "dns": ["dns"],
        "http": ["http"],
        "ssl": ["ssl"],
        "conn": ["conn"],
        "ssh": ["ssh"],
        "notice": ["notice"],
    }
    log_types = type_map.get(index, ["conn", "dns", "suricata_corelight"])

    hours = int(time_range.get("hours", 24))
    terms = [t.lower() for t in query.split() if len(t) > 2]
    if not terms:
        return []

    matched: list[dict] = []
    for lt in log_types:
        events = _load_zeek_events(lt, max_files=8, max_events=200)
        events = _filter_by_time(events, hours=hours)
        for evt in events:
            evt_str = json.dumps(evt, default=str).lower()
            if any(term in evt_str for term in terms):
                matched.append(_format_ts(_slim_event(evt)))
                if len(matched) >= 50:
                    break
        if len(matched) >= 50:
            break

    return matched[:50]


async def query_log_type(
    log_type: str,
    filters: dict[str, Any] | None = None,
    time_range: dict[str, Any] | None = None,
    max_events: int = 50,
) -> list[dict]:
    """Generic query for any Zeek log type (http, ssl, ssh, notice, etc.)."""
    hours = int((time_range or {}).get("hours", 24))
    events = _load_zeek_events(log_type, max_files=10, max_events=300)
    events = _filter_by_time(events, hours=hours)
    if filters:
        events = _match_filters(events, filters)
    events = [_format_ts(_slim_event(e)) for e in events]
    events.sort(key=lambda e: e.get("ts", 0), reverse=True)
    return events[:max_events]


# ---------------------------------------------------------------------------
# Session correlation — uid links all logs from the same network session
# ---------------------------------------------------------------------------

async def correlate_by_uid(
    uids: list[str],
    time_range: dict[str, Any] | None = None,
) -> dict[str, list[dict]]:
    """Given a list of Zeek uids, find all related events across log types.

    Corelight core concept: the same uid appears in conn, dns, http, ssl,
    files, suricata_corelight, etc. for the same network session.
    Returns {log_type: [events]} grouped by source type.

    Uses grep_pattern on the first uid for targeted searching when only
    a small number of uids are provided.
    """
    if not uids:
        return {}

    uid_set = set(uids)
    hours = int((time_range or {}).get("hours", 48))
    correlated: dict[str, list[dict]] = {}

    # Use grep_pattern for targeted search when we have few uids
    grep = uids[0] if len(uids) <= 3 else None

    # Check the most relevant log types for session context
    for log_type in ["dns", "http", "ssl", "files", "notice", "suricata_corelight"]:
        max_f = 20 if grep else 10
        events = _load_zeek_events(log_type, max_files=max_f, max_events=300, grep_pattern=grep)
        events = _filter_by_time(events, hours=hours)
        matched = [_format_ts(_slim_event(e)) for e in events if e.get("uid") in uid_set]
        if matched:
            correlated[log_type] = matched[:20]

    logger.info("uid correlation: %d uids → %s",
                len(uid_set),
                {k: len(v) for k, v in correlated.items()})
    return correlated


async def correlate_by_fuid(
    fuids: list[str],
    time_range: dict[str, Any] | None = None,
) -> list[dict]:
    """Given Zeek file UIDs (fuids), find related file events.

    Corelight core concept: fuid links file-related events across sourcetypes
    (files log contains md5/sha256 hashes, mime types, sizes).
    """
    if not fuids:
        return []

    fuid_set = set(fuids)
    hours = int((time_range or {}).get("hours", 48))
    events = _load_zeek_events("files", max_files=10, max_events=200)
    events = _filter_by_time(events, hours=hours)

    matched = []
    for evt in events:
        if evt.get("fuid") in fuid_set:
            matched.append(_format_ts(_slim_event(evt)))

    logger.info("fuid correlation: %d fuids → %d file events", len(fuid_set), len(matched))
    return matched[:30]


async def enrich_session(uid: str, time_range: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a full picture of a single network session from its uid.

    Looks up the uid across conn (base connection), dns, http, ssl, files,
    and suricata to show everything that happened in one session.
    """
    hours = int((time_range or {}).get("hours", 48))
    session: dict[str, Any] = {"uid": uid, "log_types_found": []}

    # Get the base connection
    conn_events = _load_zeek_events("conn", max_files=10, max_events=300)
    conn_events = _filter_by_time(conn_events, hours=hours)
    conn_match = [e for e in conn_events if e.get("uid") == uid]
    if conn_match:
        session["conn"] = _format_ts(_slim_event(conn_match[0]))
        session["log_types_found"].append("conn")

    # Correlate across other log types
    correlated = await correlate_by_uid([uid], time_range)
    for lt, events in correlated.items():
        session[lt] = events[:5]
        session["log_types_found"].append(lt)

    return session


async def get_session_context_for_alerts(
    alerts: list[dict],
    time_range: dict[str, Any] | None = None,
) -> list[dict]:
    """Enrich Suricata alerts with correlated session data.

    For each alert, uses its uid to look up DNS queries, HTTP requests,
    SSL SNI, and file transfers from the same network session.
    """
    if not alerts:
        return alerts

    # Collect uids from alerts
    uids = [a.get("uid") for a in alerts if a.get("uid")]
    if not uids:
        return alerts

    # Batch-load correlated data
    correlated = await correlate_by_uid(uids, time_range)

    # Build uid → context lookup
    uid_dns: dict[str, list[str]] = {}
    uid_http: dict[str, list[str]] = {}
    uid_ssl: dict[str, list[str]] = {}

    for evt in correlated.get("dns", []):
        u = evt.get("uid")
        if u:
            uid_dns.setdefault(u, []).append(evt.get("query", ""))

    for evt in correlated.get("http", []):
        u = evt.get("uid")
        if u:
            host = evt.get("host", "")
            uri = evt.get("uri", "")[:80]
            method = evt.get("method", "")
            uid_http.setdefault(u, []).append(f"{method} {host}{uri}")

    for evt in correlated.get("ssl", []):
        u = evt.get("uid")
        if u:
            uid_ssl.setdefault(u, []).append(evt.get("server_name", ""))

    # Enrich each alert
    for alert in alerts:
        uid = alert.get("uid")
        if not uid:
            continue
        ctx: dict[str, Any] = {}
        if uid in uid_dns:
            ctx["dns_queries"] = uid_dns[uid][:3]
        if uid in uid_http:
            ctx["http_requests"] = uid_http[uid][:3]
        if uid in uid_ssl:
            ctx["ssl_sni"] = uid_ssl[uid][:3]
        if ctx:
            alert["session_context"] = ctx

    return alerts


async def investigate_ip(
    ip: str,
    time_range: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Deep investigation of an IP — connections, DNS, alerts, files, sessions.

    Uses grep_pattern to efficiently scan many files for the specific IP
    without loading all records. Then uses uid correlation to pull in
    DNS, HTTP, SSL, and files context from the same sessions.
    """
    hours = int((time_range or {}).get("hours", 48))
    result: dict[str, Any] = {
        "ip": ip,
        "connections": [],
        "dns_queries": [],
        "alerts": [],
        "ssl_sessions": [],
        "files": [],
        "services_seen": set(),
        "dest_ips": set(),
        "dest_ports": set(),
        "networks": set(),
        "total_bytes_sent": 0,
        "total_bytes_recv": 0,
    }

    # 1. Grep conn files for this specific IP (scan more files, targeted)
    ip_conns = _load_zeek_events(
        "conn", max_files=30, max_events=200, grep_pattern=ip
    )
    ip_conns = _filter_by_time(ip_conns, hours=hours)
    # Double-check the IP is in the right field
    ip_conns = [e for e in ip_conns
                if e.get("id.orig_h") == ip or e.get("id.resp_h") == ip]

    uids: list[str] = []
    for c in ip_conns:
        uid = c.get("uid", "")
        if uid:
            uids.append(uid)
        if c.get("id.orig_h") == ip:
            result["dest_ips"].add(c.get("id.resp_h", ""))
            result["dest_ports"].add(c.get("id.resp_p"))
            result["total_bytes_sent"] += c.get("orig_bytes") or 0
            result["total_bytes_recv"] += c.get("resp_bytes") or 0
        else:
            result["total_bytes_recv"] += c.get("orig_bytes") or 0
            result["total_bytes_sent"] += c.get("resp_bytes") or 0
        svc = c.get("service")
        if svc:
            result["services_seen"].add(svc)
        net = c.get("id.orig_network_name") if c.get("id.orig_h") == ip else c.get("id.resp_network_name")
        if net:
            result["networks"].add(net)

    result["connections"] = [_format_ts(_slim_event(c)) for c in ip_conns[:20]]

    # 2. Grep DNS for this IP
    dns_events = _load_zeek_events(
        "dns", max_files=20, max_events=100, grep_pattern=ip
    )
    dns_events = _filter_by_time(dns_events, hours=hours)
    dns_events = [e for e in dns_events if e.get("id.orig_h") == ip]
    result["dns_queries"] = [_format_ts(_slim_event(e)) for e in dns_events[:15]]
    # Collect uids from DNS too
    for d in dns_events:
        uid = d.get("uid")
        if uid:
            uids.append(uid)

    # 3. Grep SSL for this IP
    ssl_events = _load_zeek_events(
        "ssl", max_files=15, max_events=50, grep_pattern=ip
    )
    ssl_events = _filter_by_time(ssl_events, hours=hours)
    ssl_events = [e for e in ssl_events
                  if e.get("id.orig_h") == ip or e.get("id.resp_h") == ip]
    result["ssl_sessions"] = [_format_ts(_slim_event(e)) for e in ssl_events[:15]]

    # 4. Grep HTTP for this IP
    http_events = _load_zeek_events(
        "http", max_files=15, max_events=50, grep_pattern=ip
    )
    http_events = _filter_by_time(http_events, hours=hours)
    http_events = [e for e in http_events
                   if e.get("id.orig_h") == ip or e.get("id.resp_h") == ip]
    result["http_requests"] = [_format_ts(_slim_event(e)) for e in http_events[:15]]

    # 5. Grep Suricata alerts for this IP
    alert_events = _load_zeek_events(
        "suricata_corelight", max_files=20, max_events=100, grep_pattern=ip
    )
    alert_events = _filter_by_time(alert_events, hours=hours)
    ip_alerts = [_format_ts(_slim_event(e)) for e in alert_events
                 if e.get("id.orig_h") == ip or e.get("id.resp_h") == ip]
    result["alerts"] = ip_alerts[:15]

    # Convert sets to lists for JSON
    result["services_seen"] = sorted(result["services_seen"])
    result["dest_ips"] = sorted(result["dest_ips"])[:20]
    result["dest_ports"] = sorted(result["dest_ports"])[:20]
    result["networks"] = sorted(result["networks"])

    result["summary"] = {
        "total_connections": len(ip_conns),
        "unique_destinations": len(result["dest_ips"]),
        "unique_ports": len(result["dest_ports"]),
        "services": result["services_seen"],
        "networks": result["networks"],
        "bytes_sent": result["total_bytes_sent"],
        "bytes_recv": result["total_bytes_recv"],
        "alert_count": len(ip_alerts),
        "dns_query_count": len(result["dns_queries"]),
        "ssl_session_count": len(result["ssl_sessions"]),
        "http_request_count": len(result["http_requests"]),
    }

    return result
