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
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ATHENA_DATABASE: str = os.getenv("ATHENA_DATABASE", "blackhat_pope_logs")
ATHENA_WORKGROUP: str = os.getenv("ATHENA_WORKGROUP", "blackhat-pope-dev")
ATHENA_REGION: str = os.getenv("ATHENA_REGION", os.getenv("S3_REGION", "us-west-2"))

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


def sanitize_sql(sql: str) -> str:
    """Strip dangerous DDL/DML statements — only allow SELECT queries."""
    sql = sql.strip().rstrip(";")
    if _RE_DANGEROUS.search(sql):
        raise ValueError(f"Dangerous SQL detected: {sql[:200]}")
    if not sql.upper().startswith("SELECT"):
        raise ValueError(f"Only SELECT queries allowed, got: {sql[:100]}")
    return sql


def sanitize_value(val: str) -> str:
    """Escape a value for use in SQL strings (prevent injection)."""
    return val.replace("'", "''").replace("\\", "\\\\")[:500]


# ---------------------------------------------------------------------------
# Date helpers
# ---------------------------------------------------------------------------

def today_partition() -> str:
    """Return today's date as Athena partition string YYYY-MM-DD."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def date_partitions(hours: int = 24) -> list[str]:
    """Return partition dates covering the last N hours — every day inclusive.

    Previously only included the start and today; for a 7-day range that
    missed the 5 days in between. Now walks day-by-day across the span.
    """
    now = datetime.now(timezone.utc)
    dates: set[str] = {now.strftime("%Y-%m-%d")}
    if hours > 0:
        span_days = hours // 24 + (1 if hours % 24 else 0)
        for d in range(span_days + 1):
            dates.add((now - timedelta(days=d)).strftime("%Y-%m-%d"))
    return sorted(dates)


def date_filter(hours: int = 24) -> str:
    """Return SQL WHERE fragment for date partitions."""
    parts = date_partitions(hours)
    if len(parts) == 1:
        return f"dt = '{parts[0]}'"
    return f"dt IN ({', '.join(repr(d) for d in parts)})"


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
    logger.info("Athena query started: id=%s sql=%s", query_id, sql[:200])

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

    return rows, metadata


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
        if not next_token or len(rows) >= 500:
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
        conditions.append(f"query LIKE '%{sanitize_value(domain)}%'")
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
        conditions.append(f"server_name LIKE '%{sanitize_value(server_name)}%'")
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
