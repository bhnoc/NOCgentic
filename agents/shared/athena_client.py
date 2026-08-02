"""
athena_client.py — Async Athena query client for Corelight/Zeek data.

Queries pre-optimized Parquet tables in AWS Athena with full OTel tracing.

Database: blackhat_pope_logs
Workgroup: blackhat-pope-dev
Region: us-west-2

Environment variables:
    ATHENA_DATABASE   — default: blackhat_pope_logs
    ATHENA_WORKGROUP  — default: blackhat-pope-dev
    ATHENA_REGION     — default: us-west-2
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import time
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3

import ipscope

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ATHENA_DATABASE: str = os.getenv("ATHENA_DATABASE", "blackhat_pope_logs")
ATHENA_WORKGROUP: str = os.getenv("ATHENA_WORKGROUP", "blackhat-pope-dev")
ATHENA_REGION: str = os.getenv("ATHENA_REGION", os.getenv("S3_REGION", "us-west-2"))

# Max rows accumulated by _fetch_results before we stop paginating. Hitting this
# cap silently truncates the result set, so we log a WARNING when it triggers.
MAX_RESULT_ROWS: int = 500

# ---------------------------------------------------------------------------
# Result cache
# ---------------------------------------------------------------------------
#
# Keyed on the SANITIZED SQL string (sanitize_sql() runs before any cache
# lookup — never cache/serve on raw LLM output, or a query that would now be
# rejected by the allowlist/scope check could be served from a prior hit).
#
# TTL default 300s (5 min): Athena partitions are daily (dt='YYYY-MM-DD'), so
# TTL has no relationship to partition boundaries — it exists purely to bound
# staleness of a live security feed. The alerts table / demo seed refreshes on
# a multi-minute cadence, so 5 minutes is short enough that a real new alert
# shows up promptly, while long enough that the common demo-booth pattern
# ("ask the same question a couple of times in a row") reliably hits cache.
# Override with ATHENA_CACHE_TTL_SECONDS for a live show where freshness
# matters more than cache hit rate.
#
# Cached hits sleep ~1.5s (ATHENA_CACHE_HIT_DELAY_SECONDS) via asyncio.sleep
# (non-blocking) before returning, so a demo answer doesn't look suspiciously
# instant, without stalling the event loop for other concurrent requests.
_CACHE_ENABLED: bool = os.getenv("ATHENA_CACHE_ENABLED", "true").strip().lower() not in (
    "false", "0", "no", "off",
)
_CACHE_TTL_SECONDS: float = float(os.getenv("ATHENA_CACHE_TTL_SECONDS", "300"))
_CACHE_MAX_ENTRIES: int = int(os.getenv("ATHENA_CACHE_MAX_ENTRIES", "200"))
_CACHE_HIT_DELAY_SECONDS: float = float(os.getenv("ATHENA_CACHE_HIT_DELAY_SECONDS", "0.0"))

# sql -> (expires_at_monotonic, rows, metadata). OrderedDict gives us cheap
# oldest-first eviction (popitem(last=False)) once we exceed the size bound.
_query_cache: "OrderedDict[str, tuple[float, list[dict[str, str]], dict[str, Any]]]" = OrderedDict()
# Guards all cache reads/writes. execute_query awaits network I/O between the
# cache-miss check and the cache-put, so without this two concurrent identical
# queries could both miss, both hit Athena (fine, just wasteful), and then
# race on OrderedDict mutation (not fine — dict corruption under concurrent
# asyncio tasks is possible once awaits interleave mutation). A plain
# asyncio.Lock (not threading.Lock) is correct here: everything in this
# module runs on the single event loop; boto3 calls are pushed to worker
# threads via asyncio.to_thread but the cache itself is only ever touched
# from event-loop code.
_cache_lock = asyncio.Lock()


def _cache_get(key: str) -> tuple[list[dict[str, str]], dict[str, Any]] | None:
    """Return (rows, metadata) for a live cache entry, or None on miss/expiry."""
    entry = _query_cache.get(key)
    if entry is None:
        return None
    expires_at, rows, metadata = entry
    if time.monotonic() >= expires_at:
        _query_cache.pop(key, None)
        return None
    return rows, metadata


def _cache_put(key: str, rows: list[dict[str, str]], metadata: dict[str, Any]) -> None:
    """Insert/refresh a cache entry, evicting the oldest entry past the size bound."""
    _query_cache[key] = (time.monotonic() + _CACHE_TTL_SECONDS, rows, metadata)
    _query_cache.move_to_end(key)
    while len(_query_cache) > _CACHE_MAX_ENTRIES:
        _query_cache.popitem(last=False)

def _get_athena():
    """Return a fresh boto3 Athena client on every call.

    We intentionally do NOT cache the client. A cached client holds its
    originally resolved credentials; when the EC2 instance role rotates
    (every ~6 hours via IMDS) the cached client continues using stale
    creds and starts throwing "expired token" errors. boto3 Session and
    client construction is cheap (<1 ms), so per-call creation is safe
    and ensures the credential resolver re-runs and picks up fresh IMDS
    creds. Internal boto3 caching still dedupes per-session credential
    fetches from IMDS so we don't hammer the metadata service.
    """
    session_kwargs: dict[str, str] = {}
    profile = os.getenv("AWS_PROFILE")
    if profile:
        session_kwargs["profile_name"] = profile
    session = boto3.Session(region_name=ATHENA_REGION, **session_kwargs)
    return session.client("athena")


# ---------------------------------------------------------------------------
# SQL safety
# ---------------------------------------------------------------------------

_RE_DANGEROUS = re.compile(
    r"\b(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|TRUNCATE|MERGE)\b",
    re.IGNORECASE,
)

# UNION is rejected outright: the athena-hunter's generated query patterns
# (single SELECT ... FROM <table> WHERE ... GROUP BY ... ORDER BY ... LIMIT,
# optionally with JOINs/subqueries/CTEs) never legitimately need UNION, so any
# UNION here is almost certainly UNION-based injection stitching a second SELECT.
_RE_UNION = re.compile(r"\bUNION\b", re.IGNORECASE)

# SQL comment sequences used to truncate/neutralize the rest of a query.
_RE_COMMENT = re.compile(r"(--|/\*|\*/|#)")

# Dotted quads appearing anywhere in a statement, for the scope check below.
_RE_IP_LITERAL = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

# Partial dotted prefixes (2-3 octets), optionally regex-escaped, as used in
# LIKE/regexp_like subnet predicates. Matched only when followed by a separator
# or wildcard so a full quad's leading octets don't re-trigger here.
_RE_IP_PREFIX = re.compile(
    r"\b(\d{1,3}(?:\\?\.\d{1,3}){1,2})\\?\.(?=[%_*']|$)"
)


def sanitize_sql(sql: str) -> str:
    """Validate and strip dangerous SQL — only allow a single SELECT query.

    Defense-in-depth (the LLM sits in front of this, but do not rely on it):
      * DDL/DML keyword blocklist (DROP/DELETE/INSERT/... — unchanged).
      * Reject multiple statements: at most one optional trailing semicolon.
      * Reject UNION / UNION ALL (see _RE_UNION above).
      * Reject SQL comment sequences (--, /*, */, #) used to truncate queries.
    Raises ValueError on any rejection; returns the cleaned SELECT on success.
    All checks are case-insensitive and operate on the whole statement so inline
    whitespace/comment obfuscation cannot slip a keyword past a prefix check.
    """
    sql = sql.strip()

    # Allow exactly one optional trailing semicolon; anything after it (or an
    # interior semicolon) means a second stacked statement -> reject.
    if sql.endswith(";"):
        sql = sql[:-1].rstrip()
    if ";" in sql:
        raise ValueError(f"Multiple SQL statements not allowed: {sql[:200]}")

    if _RE_COMMENT.search(sql):
        raise ValueError(f"SQL comment sequence not allowed: {sql[:200]}")
    if _RE_UNION.search(sql):
        raise ValueError(f"UNION not allowed: {sql[:200]}")
    if _RE_DANGEROUS.search(sql):
        raise ValueError(f"Dangerous SQL detected: {sql[:200]}")
    if not sql.upper().startswith("SELECT"):
        raise ValueError(f"Only SELECT queries allowed, got: {sql[:100]}")

    # Scope enforcement, in code and after the LLM. The SQL-generation prompt
    # asks the model to stay in scope, but a prompt is a suggestion; this is the
    # control. Any IP literal in the statement must be in scope, so a query for
    # an out-of-scope host cannot execute even if the model is talked into
    # writing one.
    for literal in _RE_IP_LITERAL.findall(sql):
        # Only judge things that are actually addresses. A dotted-numeric token
        # like a version string ("1.2.3.400") matches the candidate pattern but
        # is not an IP, and rejecting it would break legitimate queries.
        try:
            ipaddress.ip_address(literal)
        except ValueError:
            continue
        if not ipscope.is_in_scope(literal):
            raise ValueError(f"Out-of-scope IP in query: {literal}")

    # Partial prefixes too: LIKE '192.168.1.%' and regexp_like(h, '^10\.0\.')
    # target an out-of-scope subnet without containing a full dotted quad.
    for prefix in _RE_IP_PREFIX.findall(sql):
        if ipscope.prefix_is_out_of_scope(prefix.replace("\\", "")):
            raise ValueError(f"Out-of-scope IP prefix in query: {prefix}")
    return sql


def sanitize_value(val: str) -> str:
    """Escape a value for use in an EQUALITY SQL string literal (prevent injection).

    NOTE: this deliberately does NOT escape the LIKE metacharacters % and _.
    For equality (`col = '...'`) they are ordinary characters and escaping them
    would break legit matches. For values interpolated into a LIKE pattern use
    sanitize_like_value() (which escapes %/_/\\ and requires an ESCAPE clause).
    """
    # Truncate the RAW input BEFORE escaping. Escaping first and slicing after
    # can chop a doubled '' back to a lone trailing ' at the 500-char boundary,
    # breaking out of the '...' SQL literal (injection). Truncate, then escape.
    val = val[:500]
    return val.replace("'", "''").replace("\\", "\\\\")


def sanitize_like_value(val: str) -> str:
    """Escape a value for interpolation into a LIKE pattern (prevent wildcard injection).

    Unlike sanitize_value(), this also neutralizes the LIKE metacharacters % and _
    so caller-supplied text cannot inject wildcards. Uses backslash as the escape
    char, so the surrounding query MUST append `ESCAPE '\\'`, e.g.:

        f"col LIKE '%{sanitize_like_value(v)}%' ESCAPE '\\'"

    The literal `%`/`_` wildcards the caller adds around the value stay active;
    only metacharacters *inside* the value are escaped.
    """
    val = val[:500]
    # Escape backslash first (it's the ESCAPE char), then the LIKE wildcards,
    # then finally the single-quote for the surrounding SQL string literal.
    val = val.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return val.replace("'", "''")


# ---------------------------------------------------------------------------
# Date helpers
# ---------------------------------------------------------------------------

def today_partition() -> str:
    """Return today's date as Athena partition string YYYY-MM-DD."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def date_partitions(hours: int = 24) -> list[str]:
    """Return partition dates covering the last N hours — every day inclusive.

    Walks day-by-day from the actual window start (now - hours) to today so no
    intermediate day is missed. The start day is derived from the real boundary
    rather than ceil(hours/24) days back, which previously over-generated a
    trailing extra partition (e.g. hours=1 near mid-day still emitted yesterday).
    """
    now = datetime.now(timezone.utc)
    if hours <= 0:
        return [now.strftime("%Y-%m-%d")]
    start = now - timedelta(hours=hours)
    dates: set[str] = {now.strftime("%Y-%m-%d")}
    cur = start
    while cur <= now:
        dates.add(cur.strftime("%Y-%m-%d"))
        cur += timedelta(days=1)
    return sorted(dates)


def date_filter(hours: int = 24) -> str:
    """Return SQL WHERE fragment bounding results to the last N hours.

    The dt partition list is a coarse PRUNE (whole-day granularity), not the actual
    window: "last 24h" spans two partitions (yesterday + today), so partition-only
    filtering returns up to ~48h of rows. That over-counts every metric on real data
    (two distinct capture days summed) and, in the redated dev slice, doubles counts
    exactly (each partition holds a full copy of the window). Bound BOTH ends of the
    window: `ts >= now - hours` AND `ts <= now`. The upper bound matters as much as the
    lower one: a rolling window is [now-hours, now], not [now-hours, infinity). Without
    it, any rows stamped in the FUTURE relative to now still match (e.g. the dev demo
    seeds today's 00:00-03:00 block, which is in the future when queried at 01:00, so a
    lower-only bound double-counted it against yesterday's copy). ts is epoch seconds
    (double) in every table.
    """
    parts = date_partitions(hours)
    if len(parts) == 1:
        part_clause = f"dt = '{parts[0]}'"
    else:
        part_clause = f"dt IN ({', '.join(repr(d) for d in parts)})"
    if hours <= 0:
        return part_clause
    now = datetime.now(timezone.utc)
    epoch_start = (now - timedelta(hours=hours)).timestamp()
    epoch_end = now.timestamp()
    return f"({part_clause} AND ts >= {epoch_start:.0f} AND ts <= {epoch_end:.0f})"


# ---------------------------------------------------------------------------
# Core query execution
# ---------------------------------------------------------------------------

async def execute_query(
    sql: str,
    timeout: int = 30,
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    """Execute an Athena SQL query and return (rows, metadata).

    Rows are returned as list of dicts. Metadata includes timing and bytes scanned.
    Runs the blocking boto3 calls in a thread to avoid blocking the event loop.
    """
    sql = sanitize_sql(sql)

    if _CACHE_ENABLED:
        async with _cache_lock:
            cached = _cache_get(sql)
        if cached is not None:
            rows, metadata = cached
            # Non-blocking: asyncio.sleep yields to the event loop, so other
            # concurrent requests (cache hits or cold Athena calls) are not
            # stalled while this one "looks like" it's working.
            await asyncio.sleep(_CACHE_HIT_DELAY_SECONDS)
            hit_metadata = dict(metadata)
            hit_metadata["cached"] = True
            # execution_time_ms/total_time_ms below are left as the ORIGINAL
            # cold-query timings (not overwritten with the fake delay) so a
            # caller inspecting them isn't misled about how long Athena took.
            # Callers that feed execution_time_ms into OTel duration metrics
            # (e.g. agents/athena-hunter/main.py's _athena_query_duration)
            # should check `metadata.get("cached")` and skip re-recording on
            # a hit — recording the original duration again would silently
            # double-count that histogram bucket for work that didn't happen.
            hit_metadata["cache_hit_delay_ms"] = round(_CACHE_HIT_DELAY_SECONDS * 1000, 1)
            return list(rows), hit_metadata

    athena = _get_athena()

    start_time = time.monotonic()

    # Start query
    response = await asyncio.to_thread(
        athena.start_query_execution,
        QueryString=sql,
        QueryExecutionContext={"Database": ATHENA_DATABASE},
        WorkGroup=ATHENA_WORKGROUP,
    )
    query_id = response["QueryExecutionId"]
    # Do NOT log the raw SQL body at INFO — query strings embed sanitized values
    # (internal IPs, domains) that would leak to the OTLP/S3 log archive.
    logger.info("Athena query started: id=%s", query_id)

    # Poll for completion
    elapsed = 0.0
    while elapsed < timeout:
        await asyncio.sleep(0.5)
        elapsed = time.monotonic() - start_time
        result = await asyncio.to_thread(
            athena.get_query_execution,
            QueryExecutionId=query_id,
        )
        state = result["QueryExecution"]["Status"]["State"]

        if state == "SUCCEEDED":
            break
        elif state in ("FAILED", "CANCELLED"):
            reason = result["QueryExecution"]["Status"].get(
                "StateChangeReason", "Unknown"
            )
            raise RuntimeError(f"Athena query {state}: {reason}")
    else:
        # Try to cancel on timeout
        try:
            await asyncio.to_thread(
                athena.stop_query_execution, QueryExecutionId=query_id
            )
        except Exception:
            pass
        raise TimeoutError(f"Athena query timed out after {timeout}s")

    # Get execution stats
    exec_info = result["QueryExecution"]
    stats = exec_info.get("Statistics", {})
    metadata = {
        "query_id": query_id,
        "execution_time_ms": stats.get("EngineExecutionTimeInMillis", 0),
        "data_scanned_bytes": stats.get("DataScannedInBytes", 0),
        "data_scanned_mb": round(stats.get("DataScannedInBytes", 0) / 1048576, 2),
        "total_time_ms": round((time.monotonic() - start_time) * 1000, 1),
        "state": "SUCCEEDED",
    }
    logger.info(
        "Athena query done: id=%s time=%dms scanned=%.1fMB",
        query_id,
        metadata["execution_time_ms"],
        metadata["data_scanned_mb"],
    )

    # Fetch results
    rows = await _fetch_results(query_id)

    # Row-level egress filter — second layer behind the SQL scope check, so a
    # query that reaches Athena without an explicit IP literal (a broad scan, a
    # JOIN) still cannot return out-of-scope hosts.
    kept = ipscope.filter_rows(rows)
    if len(kept) != len(rows):
        dropped = len(rows) - len(kept)
        logger.info(
            "Scope filter dropped %d/%d rows: id=%s", dropped, len(rows), query_id
        )
        metadata["rows_dropped_out_of_scope"] = dropped

    # Mark this as an uncached/original execution so callers can distinguish
    # a cold run from a later cache hit via the same "cached" field either way.
    metadata["cached"] = False

    if _CACHE_ENABLED:
        # Cache the FILTERED rows (post-ipscope).
        async with _cache_lock:
            _cache_put(sql, kept, dict(metadata))

    return kept, metadata


async def _fetch_results(query_id: str) -> list[dict[str, str]]:
    """Fetch paginated results from a completed Athena query."""
    athena = _get_athena()
    rows: list[dict[str, str]] = []
    headers: list[str] = []
    next_token: str | None = None

    while True:
        kwargs: dict[str, Any] = {"QueryExecutionId": query_id, "MaxResults": 1000}
        if next_token:
            kwargs["NextToken"] = next_token

        page = await asyncio.to_thread(athena.get_query_results, **kwargs)
        result_rows = page["ResultSet"]["Rows"]

        if not headers:
            # First row is column headers
            headers = [col.get("VarCharValue", f"col_{i}") for i, col in enumerate(result_rows[0]["Data"])]
            result_rows = result_rows[1:]

        for row in result_rows:
            values = [col.get("VarCharValue", "") for col in row["Data"]]
            rows.append(dict(zip(headers, values)))

        next_token = page.get("NextToken")
        if len(rows) >= MAX_RESULT_ROWS:
            if next_token:
                logger.warning(
                    "Athena results truncated at %d rows (more pages available): id=%s",
                    MAX_RESULT_ROWS, query_id,
                )
            break
        if not next_token:
            break

    return rows


# ---------------------------------------------------------------------------
# Convenience query builders
# ---------------------------------------------------------------------------

async def query_by_ip(
    ip: str,
    hours: int = 24,
    limit: int = 100,
) -> tuple[list[dict], dict]:
    """Get connections for an IP address.

    conn table uses raw Zeek naming: id_orig_h, id_resp_h.
    """
    safe_ip = sanitize_value(ip)
    dt = date_filter(hours)
    sql = f"""
    SELECT ts_datetime, uid, id_orig_h, id_orig_p, id_resp_h, id_resp_p,
           proto, service, duration, orig_bytes, resp_bytes, conn_state
    FROM conn
    WHERE {dt}
      AND (id_orig_h = '{safe_ip}' OR id_resp_h = '{safe_ip}')
    ORDER BY ts DESC
    LIMIT {min(limit, 500)}
    """
    return await execute_query(sql)


async def query_by_uid(
    uid: str,
    hours: int = 48,
) -> tuple[list[dict], dict]:
    """Get all logs for a session UID using the pre-computed index."""
    safe_uid = sanitize_value(uid)
    dt = date_filter(hours)
    sql = f"""
    SELECT uid, log_type, ts, ts_datetime, orig_h, resp_h, orig_network_name
    FROM uid_lookup
    WHERE {dt}
      AND uid = '{safe_uid}'
    ORDER BY ts
    """
    return await execute_query(sql)


async def query_alerts(
    hours: int = 24,
    severity: str | None = None,
    src_ip: str | None = None,
    limit: int = 100,
) -> tuple[list[dict], dict]:
    """Get alerts from the unified alerts table."""
    dt = date_filter(hours)
    conditions = [dt]
    if severity:
        conditions.append(f"severity = '{sanitize_value(severity)}'")
    if src_ip:
        safe_ip = sanitize_value(src_ip)
        conditions.append(f"(orig_h = '{safe_ip}' OR resp_h = '{safe_ip}')")
    where = " AND ".join(conditions)
    sql = f"""
    SELECT ts_datetime, alert_type, alert_name, alert_detail, severity,
           orig_h, resp_h, uid
    FROM alerts
    WHERE {where}
    ORDER BY ts DESC
    LIMIT {min(limit, 500)}
    """
    return await execute_query(sql)


async def query_dns(
    domain: str | None = None,
    client_ip: str | None = None,
    hours: int = 24,
    limit: int = 100,
) -> tuple[list[dict], dict]:
    """Search DNS query logs. dns table uses id_orig_h."""
    dt = date_filter(hours)
    conditions = [dt]
    if domain:
        conditions.append(f"query LIKE '%{sanitize_like_value(domain)}%' ESCAPE '\\'")
    if client_ip:
        conditions.append(f"id_orig_h = '{sanitize_value(client_ip)}'")
    where = " AND ".join(conditions)
    sql = f"""
    SELECT ts_datetime, uid, id_orig_h, query, qtype_name, rcode_name,
           answers, icann_domain
    FROM dns
    WHERE {where}
    ORDER BY ts DESC
    LIMIT {min(limit, 500)}
    """
    return await execute_query(sql)


async def query_top_talkers(
    hours: int = 24,
    limit: int = 20,
) -> tuple[list[dict], dict]:
    """Get top talkers by bytes. conn table uses id_orig_h."""
    dt = date_filter(hours)
    sql = f"""
    SELECT id_orig_h,
           SUM(CAST(orig_bytes AS bigint)) as bytes_sent,
           SUM(CAST(resp_bytes AS bigint)) as bytes_received,
           COUNT(*) as connection_count
    FROM conn
    WHERE {dt}
    GROUP BY id_orig_h
    ORDER BY bytes_sent DESC
    LIMIT {min(limit, 50)}
    """
    return await execute_query(sql)


async def query_ssl(
    server_name: str | None = None,
    ja3: str | None = None,
    ip: str | None = None,
    hours: int = 24,
    limit: int = 100,
) -> tuple[list[dict], dict]:
    """Search SSL/TLS logs. ssl table uses id_orig_h/id_resp_h."""
    dt = date_filter(hours)
    conditions = [dt]
    if server_name:
        conditions.append(f"server_name LIKE '%{sanitize_like_value(server_name)}%' ESCAPE '\\'")
    if ja3:
        conditions.append(f"ja3 = '{sanitize_value(ja3)}'")
    if ip:
        safe_ip = sanitize_value(ip)
        conditions.append(f"(id_orig_h = '{safe_ip}' OR id_resp_h = '{safe_ip}')")
    where = " AND ".join(conditions)
    sql = f"""
    SELECT ts_datetime, uid, id_orig_h, id_resp_h, server_name, version, cipher, ja3, ja3s
    FROM ssl
    WHERE {where}
    ORDER BY ts DESC
    LIMIT {min(limit, 500)}
    """
    return await execute_query(sql)


async def execute_custom_sql(sql: str) -> tuple[list[dict], dict]:
    """Execute a custom SELECT query (sanitized)."""
    return await execute_query(sql, timeout=30)
