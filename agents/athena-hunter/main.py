"""
Athena Hunter Agent — port 8005

Accepts POST /analyze with a query and IOCs, generates SQL via LLM,
executes against Athena (Parquet-optimized Corelight data), and uses
the LLM to synthesize threat intelligence.

This agent runs side-by-side with the S3-based threat-hunter to compare
data quality between raw TSV scanning and structured SQL queries.

Full OpenTelemetry tracing sent to Manifold.
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

# Make agents/shared importable
_SHARED = str(Path(__file__).resolve().parents[2] / "shared")
if _SHARED not in sys.path:
    sys.path.insert(0, _SHARED)

from llm_client import llm_complete, get_last_llm_metrics  # noqa: E402
from telemetry import init_telemetry, get_tracer, get_meter, instrument_fastapi_app  # noqa: E402
from athena_client import (  # noqa: E402
    execute_custom_sql,
    date_filter,
    sanitize_value,
    today_partition,
    query_by_ip,
    query_by_uid,
    query_alerts,
    query_dns,
    query_ssl,
    query_top_talkers,
)

# Initialize OTel tracing + metrics → Manifold
init_telemetry(service_name="bhnocgentic-athena-hunter")

_meter = get_meter()
_request_counter = _meter.create_counter(
    "bhnoc.athena_hunter.requests", description="Total athena-hunter requests"
)
_request_duration = _meter.create_histogram(
    "bhnoc.athena_hunter.duration_ms", unit="ms", description="Athena-hunter request latency"
)
_athena_query_counter = _meter.create_counter(
    "bhnoc.athena_hunter.queries", description="Total Athena SQL queries executed"
)
_athena_query_duration = _meter.create_histogram(
    "bhnoc.athena_hunter.query_duration_ms", unit="ms", description="Athena query latency"
)
_athena_bytes_scanned = _meter.create_histogram(
    "bhnoc.athena_hunter.bytes_scanned", unit="bytes", description="Athena data scanned"
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("athena-hunter")

# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------

_RE_INTERNAL_IP = re.compile(
    r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"
)
_RE_SECRET_TOKEN = re.compile(r"\b[A-Za-z0-9+/]{40,}\b")
_RE_PASSWORD = re.compile(r"(?i)password\s*[:=]\s*\S+")
_RE_API_KEY_PAT = re.compile(r"(?i)api[_-]?key\s*[:=]\s*\S+")

_RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
_RE_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")
_RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_RE_UID = re.compile(r"\b[A-Za-z][A-Za-z0-9]{15,25}\b")


def sanitize(text: str) -> str:
    text = _RE_INTERNAL_IP.sub("[INTERNAL-IP]", text)
    text = _RE_SECRET_TOKEN.sub("[REDACTED-SECRET]", text)
    text = _RE_PASSWORD.sub("password: [REDACTED]", text)
    text = _RE_API_KEY_PAT.sub("api_key: [REDACTED]", text)
    return text[:8000]


# ---------------------------------------------------------------------------
# IOC classification
# ---------------------------------------------------------------------------

def classify_iocs(iocs: list[str]) -> dict[str, list[str]]:
    """Classify IOCs into types."""
    classified: dict[str, list[str]] = {
        "ips": [], "domains": [], "md5s": [], "sha256s": [], "uids": [],
    }
    for ioc in iocs:
        if _RE_MD5.fullmatch(ioc):
            classified["md5s"].append(ioc)
        elif _RE_SHA256.fullmatch(ioc):
            classified["sha256s"].append(ioc)
        elif _RE_IP.fullmatch(ioc):
            parts = ioc.split(".")
            if all(0 <= int(p) <= 255 for p in parts):
                classified["ips"].append(ioc)
        elif _RE_UID.fullmatch(ioc):
            classified["uids"].append(ioc)
        elif _RE_DOMAIN.fullmatch(ioc):
            classified["domains"].append(ioc)
    return classified


# ---------------------------------------------------------------------------
# SQL generation via LLM
# ---------------------------------------------------------------------------

SQL_GEN_PROMPT = (
    "You are a SQL query generator for Corelight/Zeek network security data in AWS Athena.\n\n"
    "DATABASE: blackhat_pope_logs\n\n"
    "════════════════════════════════════════════════════════════\n"
    "CRITICAL — COLUMN PREFIX RULE (read twice):\n"
    "════════════════════════════════════════════════════════════\n"
    "Tables split into TWO families with DIFFERENT column names for IPs/ports/zones:\n\n"
    "(A) RAW ZEEK tables → **id_** prefix REQUIRED:\n"
    "    conn, dns, http, ssl, ssh, files, notice, suricata_corelight, weird\n"
    "    Column names: id_orig_h, id_resp_h, id_orig_p, id_resp_p,\n"
    "                  id_orig_network_name, id_resp_network_name,\n"
    "                  id_orig_room_name, id_resp_room_name\n"
    "    Using `orig_h` on these tables → COLUMN_NOT_FOUND error.\n\n"
    "(B) DERIVED tables → NO prefix:\n"
    "    alerts, uid_lookup, fuid_lookup\n"
    "    Column names: orig_h, resp_h, orig_p, resp_p, orig_network_name\n"
    "    (alerts has NO resp_network_name — only orig side)\n"
    "    Using `id_orig_h` on these → COLUMN_NOT_FOUND error.\n"
    "════════════════════════════════════════════════════════════\n\n"
    "VERIFIED COLUMNS per table (use exactly these names):\n"
    "- conn: uid, id_orig_h, id_orig_p, id_resp_h, id_resp_p, proto, service, duration, "
    "orig_bytes, resp_bytes, conn_state, history, id_orig_network_name, id_resp_network_name, "
    "remote_organization, remote_country, remote_asn, remote_city, app, "
    "id_orig_mac, id_orig_mac_vendor, id_resp_mac, id_resp_mac_vendor "
    "(MAC address + resolved OUI vendor per side, the reliable MAC<->IP link)\n"
    "- dns: uid, id_orig_h, id_resp_h, query, qtype_name, rcode_name, answers, "
    "icann_domain, icann_tld, id_orig_network_name\n"
    "- ssl: uid, id_orig_h, id_resp_h, server_name, version, cipher, ja3, ja3s, "
    "subject, issuer, validation_status, id_orig_network_name\n"
    "- http: uid, id_orig_h, id_resp_h, method, host, uri, user_agent, status_code, "
    "request_body_len, response_body_len, orig_fuids, resp_fuids, id_orig_network_name\n"
    "- files: fuid, uid, id_orig_h, id_resp_h, mime_type, filename, md5, sha1, sha256, "
    "seen_bytes, total_bytes, source, id_orig_network_name\n"
    "   ⚠ files has NO remote_organization — JOIN with conn on uid to get that.\n"
    "- suricata_corelight: uid, id_orig_h, id_resp_h, id_orig_p, id_resp_p, "
    "id_orig_network_name, id_resp_network_name, id_orig_room_name, id_resp_room_name, "
    "alert_action, alert_signature, alert_category, alert_severity (INT), alert_signature_id, service\n"
    "- notice: uid, id_orig_h, id_resp_h, note, msg, severity_name, severity_level, "
    "id_orig_network_name, fuid\n"
    "- alerts: uid, alert_type, alert_name, alert_detail, severity (VARCHAR), "
    "orig_h, resp_h, orig_p, resp_p, orig_network_name\n"
    "- uid_lookup: uid, log_type, orig_h, resp_h, orig_network_name (FAST index — use when "
    "you have a uid and want every related log type)\n"
    "- fuid_lookup: fuid, uid, filename, mime_type, sha256, orig_h, resp_h (FAST file index)\n"
    "- dhcp: uid, mac, host_name, client_addr, assigned_addr, requested_addr, server_addr, "
    "id_orig_h, id_resp_h (DHCP leases; host_name is the device's self-reported name)\n"
    "- All tables have: ts (epoch bigint), ts_datetime (varchar), dt (varchar YYYY-MM-DD)\n\n"
    "TYPES & ENUMS:\n"
    "- alerts.severity is VARCHAR: 'critical','high','medium','low','informational'. "
    "Use `=` or `IN (...)`; NEVER `<`/`<=`/`>`/`>=`.\n"
    "- suricata_corelight.alert_severity is INTEGER (1=highest).\n"
    "- For lateral movement / zone correlation, use suricata_corelight (has both-side zones). "
    "alerts only has orig_network_name.\n"
    "- For 'connections to Zoho/Google/AWS' style org queries, filter conn.remote_organization "
    "LIKE '%<org>%' (GeoIP enrichment).\n\n"
    "RULES:\n"
    "1. ALWAYS include a date partition filter. Pick based on the analyst's time scope:\n"
    "   - \"last N hours\" with N <= 24: `dt = 'TODAY'`\n"
    "   - \"today\" (explicit): `dt = 'TODAY'`\n"
    "   - default / \"recent\" / no time mentioned / \"any\" / \"are there\": "
    "       `dt IN ('TODAY','YESTERDAY')`   ← use a 2-day window, data rolls over hourly\n"
    "   - \"yesterday\": `dt = 'YESTERDAY'`\n"
    "   - \"last N days\" / \"past week\" / \"last week\": `dt >= 'START_DATE' AND dt <= 'TODAY'`\n"
    "   TODAY, YESTERDAY, 7 days ago are computed for you in the user content.\n"
    "2. ALWAYS include LIMIT (max 200)\n"
    "3. Only SELECT queries — no DDL/DML\n"
    "4. Match column prefix to the table: `id_orig_h` on raw Zeek tables, `orig_h` on alerts/uid_lookup\n"
    "5. For aggregations on conn use CAST(orig_bytes AS bigint)\n"
    "6. NEVER use the name 'suricata' — the table is 'suricata_corelight'\n"
    "7. For organisation/brand queries (Zoho, Google, AWS, etc.), search on MULTIPLE "
    "fields because GeoIP enrichment can be sparse: use BOTH conn.remote_organization LIKE '%Zoho%' "
    "AND ssl.server_name LIKE '%zoho%' (SSL SNI contains real hostnames like 'mdm.zoho.in'). "
    "Often the SSL match is more reliable.\n\n"
    "COMMON HUNT PATTERNS — use these when the analyst's intent matches:\n\n"
    "* Brute-force / credential attacks / password guessing:\n"
    "  Real signatures include words like 'SCAN', 'Password', 'Cracking', 'Brute', 'Login', "
    "'Credential', 'SSH', 'Auth'. Use broad LIKE matching:\n"
    "    FROM alerts WHERE dt=... AND (\n"
    "      LOWER(alert_name) LIKE '%scan%' OR LOWER(alert_name) LIKE '%brute%'\n"
    "      OR LOWER(alert_name) LIKE '%password%' OR LOWER(alert_name) LIKE '%cracking%'\n"
    "      OR LOWER(alert_name) LIKE '%login%' OR LOWER(alert_name) LIKE '%credential%'\n"
    "      OR LOWER(alert_name) LIKE '%ssh%')\n\n"
    "* Lateral movement between conference zones:\n"
    "    FROM suricata_corelight WHERE dt=...\n"
    "      AND id_orig_network_name IS NOT NULL\n"
    "      AND id_resp_network_name IS NOT NULL\n"
    "      AND id_orig_network_name <> id_resp_network_name\n"
    "  Or conn on sensitive ports for internal-to-internal:\n"
    "    FROM conn WHERE dt=... AND id_resp_p IN (22,3389,445,3306,5432,5900,1433,23)\n"
    "      AND id_orig_h LIKE '10.%' AND id_resp_h LIKE '10.%'\n\n"
    "* Beaconing / C2:\n"
    "  alert_signature/alert_name LIKE '%C2%' OR '%CnC%' OR '%Beacon%' OR '%RAT%' OR '%Trojan%'.\n"
    "  Also aggregate conn by (id_orig_h, id_resp_h) with high connection count.\n\n"
    "* Company / product / service names (Zoho, Dropbox, Google, AWS, Cloudflare, AnyDesk, "
    "NetSupport, TeamViewer, etc.):\n"
    "  The name can appear in THREE places — query ALL THREE:\n"
    "  (a) alert_name on the alerts table — many signatures embed the brand:\n"
    "      'Dropbox.com Offsite File Backup in Use', 'AnyDesk Relay Domain',\n"
    "      'NetSupport RAT CnC Activity', 'TeamViewer Connection'.\n"
    "        FROM alerts WHERE dt IN ('TODAY','YESTERDAY')\n"
    "          AND LOWER(alert_name) LIKE '%<name>%'\n"
    "  (b) SSL SNI (most reliable for active traffic):\n"
    "        FROM ssl WHERE dt IN ('TODAY','YESTERDAY')\n"
    "          AND LOWER(server_name) LIKE '%<name>%'\n"
    "  (c) conn.remote_organization (GeoIP; values can be country codes on fresh data):\n"
    "        FROM conn WHERE dt IN ('TODAY','YESTERDAY')\n"
    "          AND LOWER(remote_organization) LIKE '%<name>%'\n"
    "  Generate ALL 3 so the analyst sees alerts + active sessions + GeoIP together. "
    "If the query mentions a specific host/zone, add `AND id_orig_h='<ip>'` or "
    "`AND orig_network_name LIKE '%<zone>%'`.\n\n"
    "* Zone-scoped queries (e.g. 'from General WiFi', 'from Registration Web'):\n"
    "  On alerts: `orig_network_name LIKE '%<zone>%'`\n"
    "  On conn/dns/ssl/http/files/notice/suricata_corelight: "
    "`id_orig_network_name LIKE '%<zone>%'`\n\n"
    "* File transfers to/from a specific org (e.g. 'files from IP to Zoho'):\n"
    "  files has no remote_organization OR server_name — JOIN via uid with conn+ssl.\n"
    "  ALWAYS generate BOTH of these so the analyst sees the full picture:\n"
    "  (1) The targeted join — 'did any file transfer match the org?'\n"
    "    SELECT f.ts_datetime, f.uid, f.filename, f.mime_type, f.seen_bytes, f.sha256,\n"
    "           s.server_name, c.remote_organization, c.id_resp_h\n"
    "    FROM files f\n"
    "    JOIN conn c ON f.uid=c.uid AND f.dt=c.dt\n"
    "    LEFT JOIN ssl s ON f.uid=s.uid AND f.dt=s.dt\n"
    "    WHERE f.dt IN ('TODAY','YESTERDAY') AND c.id_orig_h='<ip>'\n"
    "      AND (LOWER(s.server_name) LIKE '%<org>%'\n"
    "           OR LOWER(c.remote_organization) LIKE '%<org>%')\n"
    "  (2) Supporting context — 'where DID the files go?' (top destinations):\n"
    "    SELECT c.id_resp_h,\n"
    "           ARBITRARY(s.server_name) AS sample_sni,\n"
    "           ARBITRARY(c.remote_organization) AS sample_org,\n"
    "           COUNT(*) AS file_count,\n"
    "           SUM(CAST(f.seen_bytes AS bigint)) AS bytes\n"
    "    FROM files f\n"
    "    JOIN conn c ON f.uid=c.uid AND f.dt=c.dt\n"
    "    LEFT JOIN ssl s ON f.uid=s.uid AND f.dt=s.dt\n"
    "    WHERE f.dt IN ('TODAY','YESTERDAY') AND c.id_orig_h='<ip>'\n"
    "    GROUP BY c.id_resp_h ORDER BY file_count DESC LIMIT 20\n"
    "  When the targeted (1) is empty but (2) has rows, tell the analyst plainly: "
    "'No files to <org>, but N files went to X, Y, Z instead.'\n\n"
    "* Device lookup by MAC address ('what do we know about MAC aa:bb:cc:...', "
    "'which device / IP is this MAC'):\n"
    "  The reliable MAC<->IP link is conn.id_orig_mac (NOT dhcp, whose coverage is sparse "
    "and may be empty for a MAC that is clearly active in conn). ALWAYS query conn first:\n"
    "    SELECT id_orig_h, COUNT(*) AS connections\n"
    "    FROM conn WHERE dt IN ('TODAY','YESTERDAY') AND id_orig_mac='<mac>'\n"
    "    GROUP BY id_orig_h ORDER BY connections DESC LIMIT 20\n"
    "  Also pull the DHCP hostname if present (may be empty, that is fine):\n"
    "    SELECT DISTINCT mac, host_name, assigned_addr FROM dhcp\n"
    "      WHERE dt IN ('TODAY','YESTERDAY') AND mac='<mac>'\n"
    "  Generate BOTH so MAC -> IP(s) + hostname surface. Match the MAC exactly; do not "
    "lowercase or reformat it. For VENDOR, do NOT rely on id_orig_mac_vendor (it is almost "
    "always 'unknown' in this data). Instead identify the vendor from the MAC's OUI, the "
    "first three octets (e.g. 00:0c:29 = VMware, ac:de:48 = Apple/private). State the OUI "
    "vendor in your answer, and note if the MAC is locally-administered/randomized (second "
    "hex digit is 2, 6, A, or E).\n\n"
    "* DNS anomalies / tunneling / exfil-shaped / RMM domains:\n"
    "  DGA-shape alone (long or NXDOMAIN queries) MISSES the important cases, because "
    "tunneling and RMM domains are SHORT and resolve fine, flagged by an IDS signature "
    "not by query length. ALWAYS generate BOTH:\n"
    "  (a) shape-based on dns (catches DGA / long / failed lookups):\n"
    "      FROM dns WHERE dt=... AND (LENGTH(query) > 50 OR rcode_name='NXDOMAIN')\n"
    "  (b) signature-based on alerts (catches Cloudflare Tunnel 'argotunnel', DoH, "
    "RMM/remote-management, P2P, DNS-over-HTTPS, fast-flux). The tunnel/RMM signal lives "
    "in alert_name, e.g. 'ET INFO DNS Query to Cloudflare Tunneling Domain (argotunnel.com)'. "
    "You MUST write (b) as a COUNT aggregate grouped by alert_name (NOT a row-by-row SELECT "
    "of ts_datetime/uid), so the dominant signature and its true volume stand out, and LEAD "
    "the answer with the highest-count signature (argotunnel is usually #1 here):\n"
    "      SELECT alert_name, COUNT(*) AS hits FROM alerts WHERE dt=... AND (\n"
    "        LOWER(alert_name) LIKE '%tunnel%' OR LOWER(alert_name) LIKE '%argotunnel%'\n"
    "        OR LOWER(alert_name) LIKE '%dns over https%' OR LOWER(alert_name) LIKE '%doh%'\n"
    "        OR LOWER(alert_name) LIKE '%rmm%' OR LOWER(alert_name) LIKE '%remote monitoring%'\n"
    "        OR LOWER(alert_name) LIKE '%fast flux%' OR LOWER(alert_name) LIKE '%exfil%'\n"
    "        OR LOWER(alert_name) LIKE '%p2p%')\n"
    "      GROUP BY alert_name ORDER BY hits DESC\n"
    "  When (a) is empty but (b) has hits, be honest: 'No DGA-shaped domains, but "
    "tunneling/RMM signatures fired: <names + counts>.'\n\n"
    "* Top talkers / exfil / outbound bytes:\n"
    "    FROM conn WHERE dt=...\n"
    "    GROUP BY id_orig_h ORDER BY SUM(CAST(resp_bytes AS bigint)) DESC LIMIT 20\n\n"
    "* Session correlation (got a uid, want everything related):\n"
    "    FROM uid_lookup WHERE dt=... AND uid='<uid>' ORDER BY ts\n"
    "  (uid_lookup uses orig_h / resp_h — NO id_ prefix.)\n\n"
    "* Vague / broad queries: widen to dt IN ('today','yesterday').\n\n"
    "CORRECTNESS CHECKS before you output SQL:\n"
    "1. Every WHERE on conn/dns/http/ssl/files/notice/suricata_corelight uses id_orig_h / id_resp_h.\n"
    "2. Every WHERE on alerts/uid_lookup/fuid_lookup uses orig_h / resp_h.\n"
    "3. Date filter present. LIMIT present (max 200).\n"
    "4. Never use `severity < N` on alerts — severity is a string enum.\n\n"
    "Generate 1-3 SQL queries to answer the analyst's question. "
    "Return ONLY a JSON array of SQL strings:\n"
    '[\"SELECT ...\", \"SELECT ...\"]\n'
    "No markdown, no explanation."
)


async def generate_sql(query: str, iocs: dict[str, list[str]], today: str) -> list[str]:
    """Use LLM to generate Athena SQL queries from natural language."""
    tracer = get_tracer()
    with tracer.start_as_current_span("athena_hunter.generate_sql") as span:
        span.set_attribute("query.length", len(query))
        span.set_attribute("query.text", query[:500])

        # Sanitize every IOC before interpolating into the prompt (mirrors what
        # _fallback_queries does) — defense-in-depth against injection via a
        # quote-bearing IOC that slipped through classification.
        ioc_ctx = ""
        if iocs["ips"]:
            _ips = [sanitize_value(v) for v in iocs["ips"][:5]]
            ioc_ctx += f"IPs to investigate: {', '.join(_ips)}\n"
        if iocs["domains"]:
            _domains = [sanitize_value(v) for v in iocs["domains"][:5]]
            ioc_ctx += f"Domains: {', '.join(_domains)}\n"
        if iocs["uids"]:
            _uids = [sanitize_value(v) for v in iocs["uids"][:3]]
            ioc_ctx += f"UIDs: {', '.join(_uids)}\n"
        if iocs["md5s"] or iocs["sha256s"]:
            _hashes = [sanitize_value(v) for v in (iocs["md5s"] + iocs["sha256s"])[:3]]
            ioc_ctx += f"Hashes: {', '.join(_hashes)}\n"

        from datetime import datetime as _dt, timedelta as _td, timezone as _tz
        _today = _dt.strptime(today, "%Y-%m-%d")
        _yesterday = (_today - _td(days=1)).strftime("%Y-%m-%d")
        _week_ago = (_today - _td(days=7)).strftime("%Y-%m-%d")
        _month_ago = (_today - _td(days=30)).strftime("%Y-%m-%d")
        # Real epoch cutoff for a rolling 24h window. The dt partition list is a
        # whole-day PRUNE: a "last 24h" query spans two partitions (today+yesterday)
        # and, without a ts bound, returns up to ~48h of rows, double-counting on
        # real data (two capture days) and exactly doubling on the redated dev slice.
        # Give the model the literal so it can bound the window precisely.
        _now = _dt.now(_tz.utc)
        _epoch_24h = int((_now - _td(hours=24)).timestamp())

        user_content = (
            f"Partition dates you may use:\n"
            f"- today: {today}\n"
            f"- yesterday: {_yesterday}\n"
            f"- 7 days ago: {_week_ago}\n"
            f"- 30 days ago: {_month_ago}\n"
            f"- epoch cutoff for exactly the last 24h (ts >= this): {_epoch_24h}\n\n"
            f"Analyst query: {query}\n\n"
            f"{ioc_ctx}"
            "Build the date filter based on the analyst's time scope. "
            "For single-day queries use `dt = 'today'`. For multi-day ranges use "
            "`dt >= 'START' AND dt <= 'today'`.\n"
            "IMPORTANT, precise 24h window: whenever you use the 2-day partition prune "
            f"`dt IN ('{today}','{_yesterday}')`, you MUST also add `AND ts >= {_epoch_24h}` "
            "so the result is exactly the last 24 hours and not ~48h. This matters most for "
            "COUNT/total/'how many' queries and any 'last 24 hours' phrasing. For a pure "
            "existence check ('are there ANY X') the extra bound is harmless, so add it too."
        )

        try:
            raw = await llm_complete(
                # Truncation guard for SQL generation. On flash-lite, thinking_budget=0
                # is clamped to -1 (UNBOUNDED dynamic thinking), and thinking tokens
                # share max_output_tokens — so a long query (e.g. a multi-LIKE brute-force
                # pattern) could still burn the budget thinking and truncate the SQL
                # mid-literal ("... LIKE '%login LIMIT 200" with an unclosed quote) →
                # Athena "mismatched input". Two-part fix: (1) a small FIXED thinking
                # budget (512) instead of unbounded dynamic, so thinking can't starve
                # output; (2) 4096 output tokens to match the synthesis call. This is a
                # pure structured-output step — it needs little thinking, lots of room.
                system_prompt=SQL_GEN_PROMPT,
                user_content=user_content,
                max_tokens=4096,
                temperature=0.0,
                thinking_budget=512,
            )
            span.set_attribute("llm.response_length", len(raw))
        except RuntimeError as exc:
            logger.warning("LLM SQL generation failed: %s", exc)
            span.set_attribute("error", str(exc))
            return _fallback_queries(query, iocs, today)

        # Parse JSON array of SQL strings
        queries = _parse_sql_response(raw)
        span.set_attribute("sql.query_count", len(queries))

        if not queries:
            logger.warning("No SQL parsed from LLM, using fallback")
            return _fallback_queries(query, iocs, today)

        # Substitute literal partition tokens the model emits (the prompt uses
        # TODAY/YESTERDAY placeholders, and the model often echoes the lowercase
        # 'today'/'yesterday' from the user content) with real YYYY-MM-DD dates.
        # Athena partitions are dt='2026-07-23', so a literal dt='today' matches
        # zero rows. Word-boundary + quote-aware so we only touch the date literal.
        _token_dates = {
            "today": today,
            "yesterday": _yesterday,
            "7_days_ago": _week_ago,
            "30_days_ago": _month_ago,
            # The prompt advertises `dt >= 'START_DATE'` / `dt >= 'START'` for
            # multi-day ranges but never defined the literal, so it survived
            # substitution and matched zero partitions. Resolve to the 7-day
            # default the user_content advertises.
            "start_date": _week_ago,
            "start": _week_ago,
        }
        def _sub_tokens(s: str) -> str:
            for tok, real in _token_dates.items():
                s = re.sub(rf"(?i)'{tok}'", f"'{real}'", s)
            return s

        # Inject date partition if missing
        validated = []
        for sql in queries[:3]:
            sql = _sub_tokens(sql)
            if "dt" not in sql.lower():
                # Try to add dt filter
                if "WHERE" in sql.upper():
                    sql = re.sub(
                        r"(?i)(WHERE\s+)",
                        f"\\1dt = '{today}' AND ",
                        sql,
                        count=1,
                    )
                else:
                    # No WHERE: insert the partition predicate BEFORE the first
                    # GROUP BY / ORDER BY / HAVING / LIMIT clause, else append.
                    # Appending blindly produced invalid SQL like
                    # "... GROUP BY x WHERE dt='...'".
                    body = sql.rstrip().rstrip(";")
                    m = re.search(r"(?i)\s+(GROUP\s+BY|ORDER\s+BY|HAVING|LIMIT)\b", body)
                    if m:
                        sql = (
                            f"{body[:m.start()]} WHERE dt = '{today}'{body[m.start():]}"
                        )
                    else:
                        sql = f"{body} WHERE dt = '{today}'"
            # Safety net for the count-doubling window bug: if the query prunes with
            # the 2-day partition form (dt IN ('a','b')) but the model omitted the ts
            # bound the prompt asked for, inject it so "last 24h" is truly 24h, not
            # ~48h. Only when there is no ts predicate already and no JOIN (a JOIN
            # makes the bare column `ts` ambiguous across aliases; leave those to the
            # prompt). The dt tokens were already substituted to real YYYY-MM-DD above.
            low = sql.lower()
            has_two_day_prune = re.search(r"dt\s+in\s*\(", low) is not None
            has_ts_bound = re.search(r"\bts\s*>=", low) is not None
            has_join = " join " in low
            if has_two_day_prune and not has_ts_bound and not has_join:
                sql = re.sub(
                    r"(?i)(dt\s+IN\s*\([^)]*\))",
                    rf"\1 AND ts >= {_epoch_24h}",
                    sql,
                    count=1,
                )
            if "LIMIT" not in sql.upper():
                sql = sql.rstrip().rstrip(";") + " LIMIT 200"
            validated.append(sql)

        return validated


def _parse_sql_response(raw: str) -> list[str]:
    """Parse SQL queries from LLM output."""
    text = raw.strip()

    # Try raw JSON
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [str(q) for q in parsed if str(q).upper().startswith("SELECT")]
    except json.JSONDecodeError:
        pass

    # Strip markdown fences
    m = re.search(r'```(?:json)?\s*\n?(.*?)\n?\s*```', text, re.DOTALL)
    if m:
        try:
            parsed = json.loads(m.group(1).strip())
            if isinstance(parsed, list):
                return [str(q) for q in parsed if str(q).upper().startswith("SELECT")]
        except json.JSONDecodeError:
            pass

    # Find array
    start = text.find("[")
    end = text.rfind("]")
    if start != -1 and end > start:
        try:
            parsed = json.loads(text[start:end + 1])
            if isinstance(parsed, list):
                return [str(q) for q in parsed if str(q).upper().startswith("SELECT")]
        except json.JSONDecodeError:
            pass

    # Last resort: extract SELECT statements
    selects = re.findall(r'(SELECT\s.+?(?:LIMIT\s+\d+|$))', text, re.IGNORECASE | re.DOTALL)
    return selects[:3]


def _fallback_queries(query: str, iocs: dict[str, list[str]], today: str) -> list[str]:
    """Generate fallback SQL when LLM fails.

    Schema reminder:
      raw Zeek tables (conn/dns/ssl/http): id_orig_h, id_resp_h
      derived tables (alerts/uid_lookup):  orig_h, resp_h
    """
    queries = []
    if iocs["ips"]:
        ip = sanitize_value(iocs["ips"][0])
        queries.append(
            f"SELECT ts_datetime, uid, id_orig_h, id_orig_p, id_resp_h, id_resp_p, "
            f"proto, service, duration, orig_bytes, resp_bytes "
            f"FROM conn WHERE dt = '{today}' "
            f"AND (id_orig_h = '{ip}' OR id_resp_h = '{ip}') "
            f"ORDER BY ts DESC LIMIT 100"
        )
        queries.append(
            f"SELECT ts_datetime, alert_type, alert_name, alert_detail, severity, uid "
            f"FROM alerts WHERE dt = '{today}' AND (orig_h = '{ip}' OR resp_h = '{ip}') "
            f"ORDER BY ts DESC LIMIT 50"
        )
    elif iocs["domains"]:
        domain = sanitize_value(iocs["domains"][0])
        queries.append(
            f"SELECT ts_datetime, id_orig_h, query, qtype_name, answers "
            f"FROM dns WHERE dt = '{today}' AND query LIKE '%{domain}%' "
            f"ORDER BY ts DESC LIMIT 100"
        )
    elif iocs["uids"]:
        uid = sanitize_value(iocs["uids"][0])
        queries.append(
            f"SELECT uid, log_type, ts_datetime, orig_h, resp_h, orig_network_name "
            f"FROM uid_lookup WHERE dt = '{today}' AND uid = '{uid}' ORDER BY ts"
        )
    else:
        queries.append(
            f"SELECT ts_datetime, alert_type, alert_name, alert_detail, severity, "
            f"orig_h, resp_h, uid FROM alerts WHERE dt = '{today}' "
            f"ORDER BY ts DESC LIMIT 100"
        )
    return queries


# ---------------------------------------------------------------------------
# Athena data gathering
# ---------------------------------------------------------------------------

async def gather_athena_context(
    iocs: list[str], query: str,
) -> dict[str, Any]:
    """Generate SQL, execute against Athena, gather results."""
    tracer = get_tracer()
    with tracer.start_as_current_span("athena_hunter.gather_context") as span:
        classified = classify_iocs(iocs)
        today = today_partition()
        span.set_attribute("iocs.ips", len(classified["ips"]))
        span.set_attribute("iocs.domains", len(classified["domains"]))
        span.set_attribute("partition.date", today)

        # Generate SQL via LLM
        sql_queries = await generate_sql(query, classified, today)
        span.set_attribute("sql.generated_count", len(sql_queries))

        ctx: dict[str, Any] = {
            "ioc_counts": {k: len(v) for k, v in classified.items()},
            "sql_queries": sql_queries,
            "query_results": [],
            "total_rows": 0,
            # True if any query returned exactly its LIMIT. The row counts are a
            # LIMIT-capped SAMPLE, not a true total, so we must not present them
            # as complete. See ql-9.
            "capped": False,
            "total_bytes_scanned": 0,
            "total_query_time_ms": 0,
            "errors": [],
        }

        # Execute each query
        for i, sql in enumerate(sql_queries):
            with tracer.start_as_current_span(f"athena_hunter.execute_sql_{i}") as qspan:
                qspan.set_attribute("sql.query", sql[:500])
                try:
                    rows, meta = await execute_custom_sql(sql)
                    qspan.set_attribute("sql.row_count", len(rows))
                    qspan.set_attribute("sql.execution_time_ms", meta["execution_time_ms"])
                    qspan.set_attribute("sql.data_scanned_mb", meta["data_scanned_mb"])

                    _athena_query_counter.add(1)
                    _athena_query_duration.record(meta["execution_time_ms"])
                    _athena_bytes_scanned.record(meta["data_scanned_bytes"])

                    ctx["query_results"].append({
                        "sql": sql,
                        "rows": rows[:100],
                        "row_count": len(rows),
                        "execution_time_ms": meta["execution_time_ms"],
                        "data_scanned_mb": meta["data_scanned_mb"],
                    })
                    ctx["total_rows"] += len(rows)
                    ctx["total_bytes_scanned"] += meta["data_scanned_bytes"]
                    ctx["total_query_time_ms"] += meta["execution_time_ms"]

                    # Cap detection: if the query hit its LIMIT, len(rows) is a
                    # sample floor, not a true count. Flag it so the answer says
                    # "at least N (sampled)" rather than "N total".
                    _lim = re.search(r"(?i)\bLIMIT\s+(\d+)", sql)
                    if _lim and len(rows) >= int(_lim.group(1)):
                        ctx["capped"] = True

                    logger.info(
                        "Athena query %d: %d rows, %dms, %.1fMB scanned",
                        i, len(rows), meta["execution_time_ms"], meta["data_scanned_mb"],
                    )
                except Exception as exc:
                    qspan.set_attribute("error", str(exc))
                    logger.warning("Athena query %d failed: %s", i, exc)
                    ctx["errors"].append({"sql": sql, "error": str(exc)})

        span.set_attribute("context.total_rows", ctx["total_rows"])
        span.set_attribute("context.total_queries", len(ctx["query_results"]))
        return ctx


# ---------------------------------------------------------------------------
# LLM analysis
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = (
    "You are a SOC analyst at Black Hat Asia 2026. You queried Corelight/Zeek "
    "telemetry via AWS Athena.\n\n"
    "CONTEXT:\n"
    "- conn = every connection; uid links related logs across sourcetypes\n"
    "- orig_h=src IP, resp_h=dst IP; orig_network_name = conference zone\n"
    "- alerts unifies Suricata + Zeek notices\n\n"
    "IMPORTANT — multiple query results may be supplied:\n"
    "- You may receive 1-3 SQL query results. READ ALL OF THEM before answering.\n"
    "- If the targeted query returns 0 rows but a supporting/context query has data, "
    "your answer must reflect that nuance. Example:\n"
    "    'No file transfers to Zoho. 1,298 files went elsewhere — top destinations: "
    "35.190.46.17 (downloads.claude.ai, 470 files, 120 MB), 142.251.156.119 (Google).'\n"
    "- Never say 'no results' when another query in the batch shows related activity.\n\n"
    "STYLE — FOLLOW EXACTLY:\n"
    "- Active voice, imperative. No hedging, no filler.\n"
    "- Skip 'Based on', 'It appears', 'The data shows', 'I analyzed'.\n"
    "- Skip meta-commentary about SQL ('The first query...', 'returned 0 rows'). "
    "Speak about the ACTIVITY, not the queries.\n"
    "- Cite specifics inline: IP, port, uid, signature, count. Copy exact IP strings "
    "verbatim — never abbreviate or drop digits.\n"
    "- No preamble, no recap of the question.\n\n"
    "FORMAT (use these three headers only):\n"
    "## Answer\n"
    "1–2 sentences, direct, synthesizing ALL query results.\n\n"
    "## Evidence\n"
    "Bullets of concrete data — IP × count, signature, timestamps, destinations. One line each.\n\n"
    "## Next Steps\n"
    "Numbered imperatives: 'Block 1.2.3.4', 'Pivot on uid=ABC123'.\n\n"
    "End with: ```json\n{\"confidence\": 0.XX}\n```\n"
    "Only cite data present in query results — never invent IPs, domains, or UIDs. "
    "If EVERY query returned 0 rows, say so in one line and set confidence < 0.3."
)


async def llm_analyze(query: str, context: dict[str, Any]) -> tuple[str, float]:
    """Send Athena results to LLM for analysis."""
    tracer = get_tracer()
    with tracer.start_as_current_span("athena_hunter.llm_analyze") as span:
        # Build context string from query results
        results_str = ""
        for qr in context.get("query_results", []):
            results_str += f"\n**SQL:** `{qr['sql'][:300]}`\n"
            results_str += f"**Rows:** {qr['row_count']} | **Time:** {qr['execution_time_ms']}ms | **Scanned:** {qr['data_scanned_mb']}MB\n"
            # Include first N rows as JSON
            sample = qr["rows"][:50]
            if sample:
                results_str += f"```json\n{json.dumps(sample, default=str)[:4000]}\n```\n"

        if context.get("errors"):
            results_str += f"\n**Query Errors:** {json.dumps(context['errors'], default=str)[:500]}\n"

        context_str = results_str[:6000]
        span.set_attribute("context.length", len(context_str))

        # When any query hit its LIMIT the row count is a capped sample, not a
        # true total; label it honestly so the answer doesn't overstate volume
        # as complete (ql-9).
        _rows = context.get("total_rows", 0)
        if context.get("capped"):
            _rows_label = (
                f"at least {_rows} rows (SAMPLED: one or more queries hit their "
                f"LIMIT, true total is higher)"
            )
        else:
            _rows_label = f"{_rows} total rows"

        user_content = (
            f"**Analyst Query:** {sanitize(query)}\n\n"
            f"**Athena Query Results ({_rows_label}, "
            f"{context.get('total_query_time_ms', 0)}ms total):**\n{context_str}"
        )

        try:
            answer = await llm_complete(
                system_prompt=SYSTEM_PROMPT,
                user_content=user_content,
                max_tokens=4096,
                temperature=0.1,
                thinking_budget=0,
            )
            span.set_attribute("llm.answer_length", len(answer))
        except RuntimeError as exc:
            span.set_attribute("error", str(exc))
            return (
                f"LLM not configured. Athena results: {json.dumps(context, default=str)[:500]}",
                0.3,
            )

        # Extract confidence. Default to a LOW sentinel on a miss: a truncated or
        # malformed answer that never emitted the ```json{"confidence":..} block
        # must not report fake-high confidence to the operator.
        confidence = 0.3
        m = re.search(r'```json\s*\{[^}]*"confidence"\s*:\s*([0-9.]+)[^}]*\}\s*```', answer)
        if m:
            try:
                confidence = max(0.0, min(1.0, float(m.group(1))))
            except ValueError:
                logger.warning("confidence value unparseable, using low default")
        else:
            logger.warning("no confidence block in LLM answer, using low default")

        return answer, confidence


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="BHNOCgentic Athena Hunter", version="0.1.0")
instrument_fastapi_app(app)


class AnalyzeRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=5000)
    extracted_iocs: list[str] = Field(default_factory=list)


class AnalyzeResponse(BaseModel):
    answer: str
    confidence: float
    agent_used: str = "athena-hunter"
    data: Any = None


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    tracer = get_tracer()
    with tracer.start_as_current_span("athena_hunter.analyze") as span:
        span.set_attribute("query.length", len(req.query))
        span.set_attribute("query.text", req.query[:500])
        span.set_attribute("iocs.count", len(req.extracted_iocs))

        start = time.monotonic()
        logger.info("analyze query_len=%d iocs=%d", len(req.query), len(req.extracted_iocs))

        # Gather data via Athena
        context = await gather_athena_context(req.extracted_iocs, req.query)

        # LLM analysis
        answer, confidence = await llm_analyze(req.query, context)

        elapsed = time.monotonic() - start
        elapsed_ms = round(elapsed * 1000, 1)
        span.set_attribute("response.confidence", confidence)
        span.set_attribute("response.elapsed_ms", elapsed_ms)
        span.set_attribute("response.length", len(answer))
        span.set_attribute("response.text", (answer or "")[:2000])
        span.set_attribute("athena.total_rows", context["total_rows"])
        span.set_attribute("athena.total_query_time_ms", context["total_query_time_ms"])
        _request_counter.add(1)
        _request_duration.record(elapsed_ms)
        logger.info(
            "analyze done elapsed=%.2fs confidence=%.2f rows=%d athena_ms=%d",
            elapsed, confidence, context["total_rows"], context["total_query_time_ms"],
        )

        # Build summary for UI
        llm_metrics = get_last_llm_metrics()
        summary_data: dict[str, Any] = {
            "iocs_searched": req.extracted_iocs,
            "ioc_counts": context.get("ioc_counts", {}),
            "sql_queries_executed": len(context.get("query_results", [])),
            "total_rows": context["total_rows"],
            # True when total_rows is a LIMIT-capped sample, not a true total (ql-9).
            "rows_capped": context.get("capped", False),
            "total_athena_time_ms": context["total_query_time_ms"],
            "total_data_scanned_mb": round(context["total_bytes_scanned"] / 1048576, 2),
            "query_details": [
                {
                    "sql": qr["sql"][:200],
                    "rows": qr["row_count"],
                    "time_ms": qr["execution_time_ms"],
                    "scanned_mb": qr["data_scanned_mb"],
                }
                for qr in context.get("query_results", [])
            ],
            "errors": context.get("errors", []),
            "llm_metrics": llm_metrics,
        }

        return AnalyzeResponse(
            answer=answer,
            confidence=confidence,
            data=summary_data,
        )


# ---------------------------------------------------------------------------
# Raw alerts endpoint (feeds the web-server alert cache)
# ---------------------------------------------------------------------------

# Mirrors of alert-triage._norm_sev's tables (NUM_SEV / _WORD_SEV) and its valid
# bucket set (SEVERITY_SCORE keys). alert-triage._norm_sev is the source of truth;
# these are kept in lockstep so the same event is labeled the same on the live
# /alerts/recent feed and in the triage view.
_NUM_SEV = {"1": "high", "2": "medium", "3": "low"}
_WORD_SEV = {
    "informational (default)": "informational",
    "notification":            "low",
    "error":                   "high",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "unknown", "low", "informational"}


def _normalize_severity(raw: str | None) -> str:
    # Behaviorally identical to alert-triage._norm_sev for all shared inputs:
    # numeric 1/2/3 -> high/medium/low; recognized words pass through; the word
    # aliases above are folded; and any unrecognized / blank / None / 4+ value
    # returns "unknown" (NOT "low") so it stays visible instead of being buried.
    s = str(raw).strip().lower()
    if s in _NUM_SEV:
        return _NUM_SEV[s]
    s = _WORD_SEV.get(s, s)
    if s not in _VALID_SEVERITIES:
        return "unknown"
    return s


_RE_ET_PREFIX = re.compile(r"^(ETPRO|ET)\s+[A-Z0-9_-]+\s+", re.IGNORECASE)


def _strip_et_prefix(text: str) -> str:
    """Strip 'ET CATEGORY' / 'ET' prefix from Suricata signatures."""
    if not text:
        return text
    return _RE_ET_PREFIX.sub("", text).strip()


def _athena_row_to_alert(row: dict[str, str]) -> dict[str, Any]:
    """Map a row from the `alerts` Athena table to the UI's Alert shape."""
    alert_name = _strip_et_prefix((row.get("alert_name") or "").strip())
    alert_detail = _strip_et_prefix((row.get("alert_detail") or "").strip())
    if alert_name and alert_detail and alert_detail != alert_name:
        description = f"{alert_name} — {alert_detail}"
    else:
        description = alert_detail or alert_name or "Unknown alert"

    # Annotate high-occurrence alerts so the UI can show "(x42)" style context
    try:
        occ = int(row.get("occurrences") or 0)
    except (ValueError, TypeError):
        occ = 0
    if occ > 1:
        description = f"{description} (×{occ})"

    ts_raw = row.get("ts_datetime", "")
    uid = row.get("uid") or ""
    orig_h = row.get("orig_h") or ""
    alert_id = (
        f"{alert_name}|{orig_h}|{ts_raw}"
        if alert_name
        else uid or f"alrt-{hash((ts_raw, description)) & 0xFFFFFFFF:08x}"
    )

    return {
        "id": alert_id,
        "timestamp": ts_raw,
        "severity": _normalize_severity(row.get("severity")),
        "source": (row.get("alert_type") or "corelight").strip().lower() or "corelight",
        "description": description[:500],
        "srcIp": orig_h or None,
        "dstIp": row.get("resp_h") or None,
    }


@app.get("/alerts/recent")
async def alerts_recent(hours: int = 1, limit: int = 100) -> dict[str, Any]:
    """Return deduplicated alerts from Athena mapped to the UI Alert shape.

    Groups by (alert_name, severity, orig_h) so a flood of one signature from
    one host shows up once (with an occurrence count) rather than 200 times.
    This is what drives the "live" alert feed trickle.
    """
    tracer = get_tracer()
    with tracer.start_as_current_span("athena_hunter.alerts_recent") as span:
        hours = max(1, min(int(hours), 24))
        limit = max(1, min(int(limit), 500))
        span.set_attribute("hours", hours)
        span.set_attribute("limit", limit)

        dt = date_filter(hours)
        # Exclude noisy ET INFO signatures — they're informational, not
        # actionable, and flood the feed with duplicates.
        sql = f"""
        SELECT
            alert_name,
            alert_type,
            severity,
            orig_h,
            MAX(ts_datetime) AS ts_datetime,
            ARBITRARY(alert_detail) AS alert_detail,
            ARBITRARY(resp_h) AS resp_h,
            ARBITRARY(uid) AS uid,
            COUNT(*) AS occurrences
        FROM alerts
        WHERE {dt}
          AND alert_name IS NOT NULL
          AND UPPER(alert_name) NOT LIKE 'ET INFO%'
          AND UPPER(alert_name) NOT LIKE 'ETPRO INFO%'
        GROUP BY alert_name, alert_type, severity, orig_h
        ORDER BY MAX(ts) DESC
        LIMIT {limit}
        """

        try:
            rows, meta = await execute_custom_sql(sql)
            alerts = [_athena_row_to_alert(r) for r in rows]
            span.set_attribute("alerts.count", len(alerts))
            span.set_attribute("athena.execution_time_ms", meta.get("execution_time_ms", 0))
            _athena_query_counter.add(1)
            _athena_query_duration.record(meta.get("execution_time_ms", 0))
            return {
                "alerts": alerts,
                "count": len(alerts),
                "hours": hours,
                "athena_ms": meta.get("execution_time_ms", 0),
                "data_scanned_mb": meta.get("data_scanned_mb", 0),
            }
        except Exception as exc:
            span.set_attribute("error", str(exc))
            logger.warning("alerts_recent failed: %s", exc)
            return {"alerts": [], "count": 0, "hours": hours, "error": str(exc)}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "agent": "athena-hunter"}


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8005, log_level="info")
