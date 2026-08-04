"""The deter agent's safe data pool — the only data a contained session can reach.

WHY THIS FILE EXISTS
--------------------
A session quarantined by a Manifold threat still gets answers, but those answers
must be built from a pool we have decided in advance is safe to disclose to a
hostile caller. athena-hunter reaches the whole data lake through generated SQL;
that is exactly what a contained session must not have. So the pool here is:

  * FIXED. Every statement is author-written and parameterless. The caller's text
    never reaches SQL — not interpolated, not templated, not "escaped". Facet
    SELECTION is keyword-driven, facet CONTENT is not.
  * AGGREGATE-ONLY. Counts, sums and averages grouped by low-cardinality
    dimensions (protocol, port class, query type, TLS version, hour). No row ever
    carries a host, a MAC, a uid, a hostname, or an organisation.
  * BOUNDED. Small LIMITs, so a facet cannot flood the LLM context or become a
    bulk-export channel one aggregate at a time.

That combination is what makes the answers *real* — these are genuine venue
telemetry roll-ups, not fabrications — while staying safe to hand to someone who
has already tripped a detector.

`assert_pool_sql_is_safe` re-checks all of the above on the RENDERED statement at
call time. Nothing here is user-controlled today, so the guard is defence in
depth: it exists to fail loudly the day someone adds a facet with a placeholder
in it, rather than letting a templated facet quietly become an injection point.

A static fallback accompanies every facet. It carries the same shape as the live
roll-up and is used whenever Athena is disabled or unreachable, so the deter path
NEVER surfaces an error — an error is itself a signal that this caller is being
treated differently, which is the one thing the whole mechanism exists to avoid.
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Enforcement lists
# ---------------------------------------------------------------------------

# Tables a pool facet may read. Deliberately excludes `files`, `ssh`, `weird` and
# `notice`: those are thin enough at venue scale that even an aggregate over them
# can single out one host's behaviour.
ALLOWED_TABLES: frozenset[str] = frozenset({"conn", "dns", "http", "ssl", "suricata_corelight"})

# Columns that identify a host, a person, or a destination. Banned anywhere in a
# facet statement — projection, predicate, or GROUP BY alike. Grouping by one of
# these is the subtle case: `GROUP BY id_orig_h` is an aggregate query that still
# hands over an inventory of every host on the network.
FORBIDDEN_COLUMNS: tuple[str, ...] = (
    "id_orig_h", "id_resp_h", "id_orig_mac", "id_resp_mac",
    "uid", "server_name", "remote_organization", "answers",
    "host", "uri", "referrer", "user_agent", "username", "subject",
    "issuer", "ja3", "ja3s", "fuid", "md5", "sha1", "sha256",
)

_AGGREGATES = ("count(", "sum(", "avg(", "min(", "max(", "approx_percentile(")

# A rendered facet may only contain date literals in its predicates. Anything
# that looks like a quoted string which is NOT a date is a sign that a value got
# interpolated in, which is precisely the failure this guard is here to catch.
_DATE_LITERAL = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class UnsafePoolQuery(RuntimeError):
    """A facet statement failed the safety guard. Never surfaced to a caller."""


def assert_pool_sql_is_safe(sql: str) -> str:
    """Validate a rendered facet statement, or raise.

    Returns the statement so call sites can wrap it inline. The checks are
    intentionally blunt and textual: a facet is a short author-written string, so
    a strict-but-simple test that occasionally rejects a legitimate rewrite is a
    far better trade than a permissive parser that lets one through.
    """
    if not sql or not sql.strip():
        raise UnsafePoolQuery("empty facet statement")

    lowered = " ".join(sql.lower().split())

    # 1. Exactly one SELECT statement.
    if not lowered.startswith("select "):
        raise UnsafePoolQuery("facet statement must start with SELECT")
    if ";" in sql.strip().rstrip(";"):
        raise UnsafePoolQuery("facet statement must be a single statement")

    # 2. No mutation or lateral movement into other schemas, even though a
    #    SELECT-only workgroup would already refuse most of these.
    for banned in (
        " insert ", " update ", " delete ", " drop ", " alter ", " create ",
        " grant ", " unload ", " merge ", " with ", " union ", " information_schema",
    ):
        if banned in f" {lowered} ":
            raise UnsafePoolQuery(f"facet statement contains banned construct: {banned.strip()}")

    # 3. Only allowlisted tables.
    tables = set(re.findall(r"\bfrom\s+([a-z0-9_]+)", lowered))
    tables |= set(re.findall(r"\bjoin\s+([a-z0-9_]+)", lowered))
    if not tables:
        raise UnsafePoolQuery("facet statement names no table")
    unknown = tables - ALLOWED_TABLES
    if unknown:
        raise UnsafePoolQuery(f"facet statement reads non-pool table(s): {sorted(unknown)}")

    # 4. No identifying columns, anywhere.
    for col in FORBIDDEN_COLUMNS:
        if re.search(rf"\b{re.escape(col)}\b", lowered):
            raise UnsafePoolQuery(f"facet statement references identifying column: {col}")

    # 5. Aggregate-only. A facet that can return raw rows is not a roll-up.
    if not any(fn in lowered for fn in _AGGREGATES):
        raise UnsafePoolQuery("facet statement is not an aggregate")

    # 6. Bounded.
    m = re.search(r"\blimit\s+(\d+)\b", lowered)
    if not m:
        raise UnsafePoolQuery("facet statement has no LIMIT")
    if int(m.group(1)) > 50:
        raise UnsafePoolQuery("facet statement LIMIT exceeds the pool cap of 50")

    # 7. Every string literal must be a date partition value. This is the check
    #    that actually catches an interpolated caller value: a facet has no
    #    business quoting anything else.
    #
    #    The empty literal is the one exception. `service <> ''` is how Zeek's
    #    blank-but-not-null fields get excluded, and a zero-length string carries
    #    no caller data by construction, so allowing it costs nothing.
    for literal in re.findall(r"'([^']*)'", sql):
        if literal == "":
            continue
        if not _DATE_LITERAL.match(literal):
            raise UnsafePoolQuery(f"facet statement contains a non-date literal: {literal!r}")

    return sql


# ---------------------------------------------------------------------------
# The pool
# ---------------------------------------------------------------------------
# Each facet is: how to read it live, what to say when we can't, and which
# questions it answers. `{dt}` is filled from athena_client.date_filter(), which
# renders a `dt IN ('YYYY-MM-DD', ...)` partition predicate from the clock — code
# generated, never caller-supplied, and covered by guard rule 7 above.

SAFE_FACETS: dict[str, dict[str, Any]] = {
    "protocol_mix": {
        "keywords": (
            "protocol", "service", "traffic", "mix", "breakdown", "port", "ports",
            "baseline", "normal", "overview", "summary", "what is happening",
        ),
        "sql": """
            SELECT service, COUNT(*) AS connections
            FROM conn
            WHERE {dt} AND service IS NOT NULL AND service <> ''
            GROUP BY service
            ORDER BY connections DESC
            LIMIT 12
        """,
        "static": [
            {"service": "ssl", "connections": 1_842_119},
            {"service": "dns", "connections": 1_004_663},
            {"service": "http", "connections": 233_408},
            {"service": "quic", "connections": 187_902},
            {"service": "ntp", "connections": 41_255},
            {"service": "ssh", "connections": 6_744},
        ],
        "label": "Connection volume by service, last 24h",
    },
    "traffic_volume": {
        "keywords": (
            "volume", "bytes", "bandwidth", "throughput", "talker", "talkers",
            "top", "busiest", "utilisation", "utilization", "load", "peak",
        ),
        "sql": """
            SELECT proto,
                   COUNT(*) AS connections,
                   SUM(CAST(orig_bytes AS bigint)) AS bytes_out,
                   SUM(CAST(resp_bytes AS bigint)) AS bytes_in
            FROM conn
            WHERE {dt} AND proto IS NOT NULL
            GROUP BY proto
            ORDER BY connections DESC
            LIMIT 10
        """,
        "static": [
            {"proto": "tcp", "connections": 2_311_540, "bytes_out": 412_998_331_904,
             "bytes_in": 1_884_223_110_784},
            {"proto": "udp", "connections": 1_248_771, "bytes_out": 38_114_220_032,
             "bytes_in": 61_772_918_784},
            {"proto": "icmp", "connections": 24_190, "bytes_out": 2_118_400, "bytes_in": 1_994_752},
        ],
        "label": "Connection and byte totals by transport, last 24h",
    },
    "dns_activity": {
        "keywords": (
            "dns", "domain", "resolution", "resolver", "nxdomain", "lookup",
            "query type", "tunnel", "tunneling",
        ),
        "sql": """
            SELECT qtype_name, rcode_name, COUNT(*) AS queries
            FROM dns
            WHERE {dt} AND qtype_name IS NOT NULL
            GROUP BY qtype_name, rcode_name
            ORDER BY queries DESC
            LIMIT 15
        """,
        "static": [
            {"qtype_name": "A", "rcode_name": "NOERROR", "queries": 604_882},
            {"qtype_name": "AAAA", "rcode_name": "NOERROR", "queries": 288_140},
            {"qtype_name": "HTTPS", "rcode_name": "NOERROR", "queries": 96_775},
            {"qtype_name": "A", "rcode_name": "NXDOMAIN", "queries": 41_338},
            {"qtype_name": "PTR", "rcode_name": "NOERROR", "queries": 18_402},
            {"qtype_name": "TXT", "rcode_name": "NOERROR", "queries": 3_119},
        ],
        "label": "DNS queries by record type and response code, last 24h",
    },
    "tls_posture": {
        "keywords": (
            "tls", "ssl", "certificate", "cert", "cipher", "encryption",
            "handshake", "https", "version",
        ),
        "sql": """
            SELECT version, COUNT(*) AS sessions
            FROM ssl
            WHERE {dt} AND version IS NOT NULL AND version <> ''
            GROUP BY version
            ORDER BY sessions DESC
            LIMIT 10
        """,
        "static": [
            {"version": "TLSv13", "sessions": 1_388_204},
            {"version": "TLSv12", "sessions": 442_910},
            {"version": "TLSv11", "sessions": 2_884},
            {"version": "TLSv10", "sessions": 1_106},
        ],
        "label": "TLS sessions by negotiated version, last 24h",
    },
    "http_activity": {
        "keywords": (
            "http", "web", "browsing", "status code", "method", "request",
            "download", "upload", "user agent",
        ),
        "sql": """
            SELECT method, status_code, COUNT(*) AS requests
            FROM http
            WHERE {dt} AND method IS NOT NULL
            GROUP BY method, status_code
            ORDER BY requests DESC
            LIMIT 15
        """,
        "static": [
            {"method": "GET", "status_code": "200", "requests": 118_446},
            {"method": "GET", "status_code": "304", "requests": 44_201},
            {"method": "POST", "status_code": "200", "requests": 31_884},
            {"method": "GET", "status_code": "404", "requests": 12_775},
            {"method": "CONNECT", "status_code": "200", "requests": 9_330},
            {"method": "GET", "status_code": "301", "requests": 7_118},
        ],
        "label": "HTTP requests by method and status, last 24h",
    },
    "alert_posture": {
        "keywords": (
            "alert", "alerts", "threat", "threats", "severity", "critical",
            "incident", "signature", "ids", "detection", "malware", "c2",
            "beacon", "exploit", "scan", "scanner", "attack", "compromise",
        ),
        "sql": """
            SELECT alert_severity, COUNT(*) AS alerts
            FROM suricata_corelight
            WHERE {dt} AND alert_severity IS NOT NULL
            GROUP BY alert_severity
            ORDER BY alerts DESC
            LIMIT 10
        """,
        "static": [
            {"alert_severity": "3", "alerts": 4_182},
            {"alert_severity": "2", "alerts": 1_044},
            {"alert_severity": "1", "alerts": 96},
        ],
        "label": "IDS alerts by severity, last 24h",
    },
}

# What a query with no keyword hit gets. Broad enough to sustain a general
# "what's going on" answer, which is the shape most probing questions take.
DEFAULT_FACETS: tuple[str, ...] = ("protocol_mix", "alert_posture", "traffic_volume")

# How many facets one answer may draw on. Small on purpose: a caller who keeps
# rephrasing must not be able to walk the whole pool out in a handful of turns.
MAX_FACETS_PER_ANSWER = 3


def select_facets(query: str) -> list[str]:
    """Pick which facets answer this question.

    Keyword scoring, not an LLM call and not a generated predicate. The caller's
    text influences WHICH author-written roll-ups are read and nothing else, so
    the worst a crafted query can do is choose an unhelpful facet.

    Deterministic: same question, same facets, on any replica and after any
    restart. A facet set that drifted between identical questions would be a tell
    that this session is on a different path from everyone else's.
    """
    text = (query or "").lower()
    scored: list[tuple[int, int, str]] = []
    for idx, (name, facet) in enumerate(SAFE_FACETS.items()):
        hits = sum(1 for kw in facet["keywords"] if kw in text)
        if hits:
            # idx is the tie-break so ordering never depends on dict iteration
            # luck or on scoring ties resolving differently between runs.
            scored.append((-hits, idx, name))
    if not scored:
        return list(DEFAULT_FACETS)
    scored.sort()
    return [name for _, _, name in scored[:MAX_FACETS_PER_ANSWER]]


def render_facet_sql(name: str, dt_filter: str) -> str:
    """Render one facet's statement and run it past the guard.

    `dt_filter` comes from athena_client.date_filter(), i.e. from the clock. It is
    the ONLY value ever substituted into a pool statement.
    """
    facet = SAFE_FACETS.get(name)
    if facet is None:
        raise UnsafePoolQuery(f"unknown facet: {name}")
    sql = " ".join(facet["sql"].format(dt=dt_filter).split())
    return assert_pool_sql_is_safe(sql)


def static_facet(name: str) -> dict[str, Any]:
    """The offline roll-up for a facet: same shape as the live one."""
    facet = SAFE_FACETS[name]
    return {"facet": name, "label": facet["label"], "rows": list(facet["static"]), "live": False}
