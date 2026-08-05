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

import asyncio
import hashlib
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

import credscrub  # noqa: E402
import ipscope  # noqa: E402
from llm_sanitize import sanitize_for_llm  # noqa: E402
from event import EVENT_LABEL  # noqa: E402
from llm_client import (  # noqa: E402
    llm_complete, get_last_llm_metrics,
    SQLGEN_PROVIDER, SQLGEN_MODEL, LLM_PROVIDER,
)
from telemetry import (  # noqa: E402
    init_telemetry, get_tracer, get_meter, instrument_fastapi_app,
    set_agent_span, set_chain_span, set_tool_span, set_tool_resource,
)
from athena_client import (  # noqa: E402
    ATHENA_DATABASE,
    execute_custom_sql,
    date_filter,
    local_day_bounds,
    local_day_partitions,
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
_athena_cache_hit_counter = _meter.create_counter(
    "bhnoc.athena_hunter.cache_hits", description="Queries served from the result cache"
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


_RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
_RE_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")
_RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_RE_UID = re.compile(r"\b[A-Za-z][A-Za-z0-9]{15,25}\b")

# A database qualifier in a table position: `FROM some_db.conn` -> `FROM conn`.
# Anchored on FROM/JOIN because a qualified COLUMN (`f.uid`) is legitimate and must
# survive untouched. The database comes from the Athena execution context, so a
# name in the SQL is at best redundant and at worst a stale one baked into a
# fine-tune. Only a single qualifier is stripped: `cat.db.tbl` keeps `db.tbl`,
# which is a deliberate choice not to guess at cross-catalog intent.
_RE_DB_QUALIFIER = re.compile(
    r"(?i)\b(from|join)(\s+)[a-z_][a-z0-9_]*\.(?=[a-z_][a-z0-9_]*\b)"
)

# Tables with NO ts column. They are one row PER HOST (or per view build), not per
# session, so there is no event time to bound. The ts back-fill below must skip them
# or it turns a working query into COLUMN_NOT_FOUND, which trades an undercount for
# no answer at all. Confirmed against information_schema on prod 2026-08-04: of 114
# tables, 87 have ts; the ones the hunter can actually reach and that lack it are
# these. dt is still present on all of them, so the partition prune stays.
_TABLES_WITHOUT_TS = frozenset({
    "entity_context",
    "asset_classification",
    "device_links",
    "dhcp_fp_lite",
    "corelight_ml_metrics",
    "corelight_raw",
    "loaded_scripts_polaris",
    "smartpcap",
    "suricata_stats",
})

_RE_TABLE_REF = re.compile(r"(?i)\b(?:FROM|JOIN)\s+(?:[a-z_][a-z0-9_]*\.)?([a-z_][a-z0-9_]*)")


def _query_supports_ts(sql: str) -> bool:
    """Can a bare `ts` predicate be added to this query?

    Only if every table it reads has a ts column. Dated view snapshots
    (entity_context_2026_08_04) share the base table's shape, so match on the
    stripped stem too rather than listing every dated variant.
    """
    for t in _RE_TABLE_REF.findall(sql):
        t = t.lower()
        stem = re.sub(r"_\d{4}_\d{2}_\d{2}$", "", t)
        if t in _TABLES_WITHOUT_TS or stem in _TABLES_WITHOUT_TS:
            return False
    return True


# ---------------------------------------------------------------------------
# The id_ prefix families, and the repair for getting them backwards.
#
# RULE 3 in the prompt says raw Zeek tables use id_orig_h and the derived tables use
# bare orig_h, with the SELECT-list caveat spelled out. v4 still gets it wrong on
# roughly 3 of 23 probe queries, usually by filtering correctly and then selecting
# the other family's name in the same statement. The prompt has been told twice; a
# third paragraph is not going to land, and the failure mode is COLUMN_NOT_FOUND,
# so the analyst gets nothing.
#
# This is safe to repair in code for one specific reason, verified against
# information_schema on prod 2026-08-04: NO table in the catalog has columns from
# both families. 60 tables are id_-prefixed, 5 are bare, 0 are both. So for any
# single-table query the correct family is decided by the table alone and the
# rewrite has no judgement to exercise.
#
# Deliberately NOT attempted:
#   * multi-table queries. A join can legitimately mix families
#     (alerts.orig_h = conn.id_orig_h) and picking one would break the other side.
#   * qualified references (`a.orig_h`). The alias tells us nothing about which
#     table it points at without parsing the FROM clause.
#   * wrong-TABLE errors, which is the rest of what the probe found: `confidence`
#     lives on asset_classification and device_links, `alert_severity` only on
#     suricata_corelight. Moving a column to the right table means rewriting the
#     FROM clause and the join keys, i.e. inventing a different query than the one
#     the model wrote. Those stay prompt-side problems.
_PREFIXED_BASE = ("orig_h", "resp_h", "orig_p", "resp_p")
# Bare-column tables, from the census. Everything else that carries these columns
# at all is id_-prefixed, but an unknown table is left alone rather than assumed.
_BARE_COLUMN_TABLES = frozenset({
    "alerts", "encrypted_dns", "fuid_lookup", "smb_sessions", "uid_lookup",
})
_PREFIXED_COLUMN_TABLES = frozenset({
    "analyzer", "bacnet", "bacnet_property", "bsap_ip_header", "conn", "conn_long",
    "corelight_ml_results", "dce_rpc", "dce_rpc_activity", "dns", "enip", "files",
    "files_metadata", "ftp", "geo", "gssapi", "http", "http2", "ipsec", "kerberos",
    "krb5_auth", "ldap", "ldap_search", "mqtt_connect", "mqtt_publish",
    "mqtt_subscribe", "mysql", "notice", "ntlm", "ntp", "pe", "perf", "postgresql",
    "profinet", "profinet_dce_rpc", "quic", "radius", "rdp", "redis", "rfb", "sip",
    "smtp", "smtp_links", "snmp", "socks", "srv_infer", "ssdp", "ssh", "ssl",
    "suricata_corelight", "syslog", "telnet", "tunnel", "vpn", "websocket",
    "websocket_messages", "weird", "wireguard", "yara_corelight",
    "yara_error_corelight",
})

# Unqualified only: no leading dot or word char, and not already carrying the id_
# prefix. The lookbehind on `_` is what keeps `id_orig_h` and `orig_l2_addr` intact.
_RE_BARE_ENDPOINT = re.compile(
    r"(?<![.\w])(" + "|".join(_PREFIXED_BASE) + r")\b")
_RE_PREFIXED_ENDPOINT = re.compile(
    r"(?<![.\w])id_(" + "|".join(_PREFIXED_BASE) + r")\b")


def _fix_endpoint_prefix(sql: str) -> str:
    """Align bare/id_-prefixed endpoint columns with the single table being read.

    A no-op unless the query reads exactly one known table, because that is the only
    case where the right answer is unambiguous. An `AS orig_h` alias is left alone:
    it is a output label, not a column reference, and renaming it would change the
    result headers the answer text refers to.
    """
    tables = {t.lower() for t in _RE_TABLE_REF.findall(sql)}
    if len(tables) != 1:
        return sql
    table = next(iter(tables))
    stem = re.sub(r"_\d{4}_\d{2}_\d{2}$", "", table)

    def _protect_aliases(s: str) -> tuple[str, list[str]]:
        held: list[str] = []

        def _hold(m: re.Match) -> str:
            held.append(m.group(0))
            return f"\x00{len(held) - 1}\x00"

        return re.sub(r"(?i)\bAS\s+(?:id_)?(?:orig|resp)_[hp]\b", _hold, s), held

    def _restore(s: str, held: list[str]) -> str:
        for i, txt in enumerate(held):
            s = s.replace(f"\x00{i}\x00", txt)
        return s

    if table in _PREFIXED_COLUMN_TABLES or stem in _PREFIXED_COLUMN_TABLES:
        sql, held = _protect_aliases(sql)
        return _restore(_RE_BARE_ENDPOINT.sub(r"id_\1", sql), held)
    if table in _BARE_COLUMN_TABLES or stem in _BARE_COLUMN_TABLES:
        sql, held = _protect_aliases(sql)
        return _restore(_RE_PREFIXED_ENDPOINT.sub(r"\1", sql), held)
    return sql


# ---------------------------------------------------------------------------
# Near-miss column names on a single table.
#
# The last two Athena failures on the AQLight v4 probe, both COLUMN_NOT_FOUND on a
# SELECT-list column that does not exist on the one table being read:
#
#   SELECT ..., alert_severity FROM alerts        -- alerts has `severity`
#   SELECT ..., confidence FROM entity_context    -- it has `id_confidence`
#
# The prompt already says both, explicitly and by name ("alerts has NO
# alert_severity ... the severity is `severity`", and id_confidence is in the column
# list). Telling it a third time is not a plan. Both are the same shape as the id_
# prefix bug: the model reached for a plausible synonym of a column that really is
# on that table.
#
# Each entry below is only allowed to exist because the target is unambiguous ON
# THAT TABLE, verified against information_schema on prod 2026-08-04: `alerts` has
# exactly one severity column out of 13, and `entity_context` has exactly one
# id-confidence column (the other four are org_/owner_name_/internal_domain_/home_,
# which are confidences about DIFFERENT things and would be a guess).
#
# This is deliberately a per-table synonym table and not a fuzzy matcher. A fuzzy
# match on `confidence` against entity_context has five candidates and would pick
# one by edit distance, which is how you turn a visible error into a wrong answer.
_COLUMN_SYNONYMS: dict[str, dict[str, str]] = {
    "alerts": {
        # Bare `severity` is the real column. suricata_corelight is where
        # alert_severity lives, and the model is borrowing the name across tables.
        "alert_severity": "severity",
        "alert_signature": "alert_name",
        "alert_category": "alert_type",
    },
    "entity_context": {
        # NOT the org_/owner_name_/internal_domain_/home_ confidences: those answer
        # different questions. id_confidence is the one about the host identity,
        # which is what "tell me about this host" is asking.
        "confidence": "id_confidence",
    },
}


def _fix_column_synonyms(sql: str) -> str:
    """Rename known near-miss columns to the real one on this table.

    Single-table queries only, and unqualified references only, for the same reason
    as _fix_endpoint_prefix: with two tables in play the name might belong to the
    other one, and an alias needs FROM-clause resolution to attribute. An `AS`
    alias is left alone because it is a result header, not a column reference.
    """
    tables = {t.lower() for t in _RE_TABLE_REF.findall(sql)}
    if len(tables) != 1:
        return sql
    table = next(iter(tables))
    stem = re.sub(r"_\d{4}_\d{2}_\d{2}$", "", table)
    syn = _COLUMN_SYNONYMS.get(table) or _COLUMN_SYNONYMS.get(stem)
    if not syn:
        return sql
    for wrong, right in syn.items():
        # (?<![.\w]) keeps qualified refs and longer names containing this one out.
        # (?<!AS ) keeps an output alias of the same name from being renamed.
        sql = re.sub(rf"(?i)(?<!AS )(?<![.\w]){wrong}\b", right, sql)
    return sql


# sanitize() lives in agents/shared/llm_sanitize.py: it was four identical
# copies, and a policy change had to be made in all four without missing one.
sanitize = sanitize_for_llm


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
    f"DATABASE: {ATHENA_DATABASE}\n\n"
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
    "    Using `id_orig_h` on these → COLUMN_NOT_FOUND error.\n\n"
    "(C) HOST-KEYED tables → the host column is `ip` or `host_ip`, NOT orig_h:\n"
    "    entity_context, asset_classification, device_links  -> ip\n"
    "    known_users, known_devices, known_names, known_domains,\n"
    "    known_hosts, known_services, known_certs -> host_ip\n"
    "    These are one row PER HOST, not per session. To attach them to a session\n"
    "    or an alert, join on the host: ON entity_context.ip = alerts.orig_h\n"
    # v4 got the prefix right in WHERE and wrong in SELECT on the same query
    # (`SELECT orig_h, resp_h ... FROM conn WHERE id_orig_h = ...`). The rule reads
    # like a filtering rule unless you say otherwise, so say otherwise.
    "\nThis applies to the SELECT list, GROUP BY and ORDER BY exactly as it applies\n"
    "to WHERE. `SELECT orig_h FROM conn` fails even when the WHERE clause correctly\n"
    "uses id_orig_h. Alias if you want a clean header: `SELECT id_orig_h AS orig_h`.\n"
    "════════════════════════════════════════════════════════════\n\n"
    "VERIFIED COLUMNS per table (use exactly these names):\n"
    "- conn: uid, id_orig_h, id_orig_p, id_resp_h, id_resp_p, proto, service, duration, "
    "orig_bytes, resp_bytes, conn_state, history, id_orig_network_name, id_resp_network_name, "
    "remote_organization, remote_country, remote_asn, remote_city, app, "
    # These were documented as id_orig_mac / id_orig_mac_vendor / id_resp_mac /
    # id_resp_mac_vendor, none of which exist. Checked against information_schema on
    # prod 2026-08-04: conn carries orig_l2_addr and resp_l2_addr and no vendor column
    # at all. A prompt that advertises a column the catalog does not have is worse
    # than silence, because the model uses it and the query dies COLUMN_NOT_FOUND.
    # For a resolved OUI vendor, entity_context.vendor_mac is the real source.
    "orig_l2_addr, resp_l2_addr "
    "(MAC per side; conn has NO vendor column, use entity_context.vendor_mac)\n"
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
    "alert_action, alert_signature, alert_category, alert_severity (STRING '1'-'4'), "
    "alert_signature_id, service\n"
    "- notice: uid, id_orig_h, id_resp_h, note, msg, severity_name, severity_level, "
    "id_orig_network_name, fuid\n"
    # v4 wrote `a.alert_signature` against alerts on the 2026-08-04 bench, which is
    # the one column it invents on this table, and the query dies with
    # COLUMN_NOT_FOUND. Name the mistake and its fix inline, since a rule stated
    # somewhere else loses to the shape of this line.
    "- alerts: ts_datetime, ts, uid, orig_h, orig_p, resp_h, resp_p, orig_network_name, "
    "alert_type, alert_name, alert_detail, severity, dt. "
    "⚠ alerts has NO alert_signature / alert_category / alert_severity: those live on "
    "suricata_corelight only. On alerts the signature text is `alert_name` and the "
    "severity is `severity`. alert_type is one of "
    # Live prod emits exactly these four. The view builder also has an 'anomaly'
    # arm, but it is discovery-driven and there is no `anomaly` table in either
    # database, so that arm is not in the deployed view. Advertising the type
    # here made a filter on it return zero rows and a confident "no anomaly
    # alerts found", which reads as a finding rather than as a missing source.
    "suricata|notice|ml|yara, so filter on it to ask about one detector. "
    "Do NOT filter alert_type='anomaly': that source is not present, so it "
    "yields an empty result that looks like a real all-clear. "
    "severity is critical|high|medium|low|informational|unknown.\n"
    "- uid_lookup: uid, log_type, ts, ts_datetime, orig_h, resp_h, orig_network_name, dt. "
    "FAST index covering EVERY log type that carries a uid (37 of them), so this is how "
    "you get the full story of one network session. log_type tells you which log a row "
    "came from; join back to that table on uid for its specific columns.\n"
    "- fuid_lookup: fuid, log_type, ts, ts_datetime, orig_h, resp_h, orig_network_name, "
    "filename, mime_type, sha256, md5, dt (FAST file index across every fuid-bearing log)\n"
    # Verified against the live schema 2026-08-01. This line previously claimed
    # `uid`, `id_orig_h` and `id_resp_h`, none of which exist on dhcp: the uid
    # column is `uids` (PLURAL, an array-ish string) and there are no id_ columns
    # at all. Any query the model wrote from the old line failed COLUMN_NOT_FOUND.
    "- dhcp: uids (PLURAL, not uid), mac, host_name, client_fqdn, domain, "
    "client_addr, assigned_addr, requested_addr, server_addr, lease_time, msg_types "
    "(DHCP leases. NO id_orig_h / id_resp_h on this table: the host is "
    "`client_addr` or `assigned_addr`. host_name is the device's self-reported name.)\n"
    "- asset_classification: ip, mac, vendor_mac, hostname, os_name, device_type, "
    "os_source, device_source, "
    "user_agent, org_name, mgmt_tooling, randomized_mac, connections, mb_in, mb_out, "
    "first_seen, last_seen, network_name, room_name, confidence, dt (device inventory, "
    "one row per host per day). Use for 'what/whose device is this'. Notes: os_name and "
    "device_type are inferred from several signals in precedence order, and "
    "os_source/device_source name WHICH one won ('user_agent' is direct evidence; "
    "'software' and 'dhcp_hostname' are weaker inference; 'unknown' means no signal "
    "landed). Cite the source when reporting an OS, and never present an inferred "
    "value as certain. mac/hostname/traffic are populated even when the OS is unknown. "
    "org_name is the "
    "SharePoint or Okta tenant, the strongest attribution signal available. "
    "randomized_mac=true explains an unknown vendor_mac as privacy behaviour rather than "
    "missing data. confidence says how many signals backed the row: prefer high/medium "
    "when attributing a device to a person or org.\n"
    # Corelight's "known_*" inventory family. All share the same spine
    # (host_ip, kuid, annotations, ts/ts_datetime/dt) and differ by what they
    # record about the host. These already existed in the catalog with real data
    # but only known_devices was documented here, so the model never queried the
    # rest: an undocumented table is an invisible table.
    "- known_devices: host_ip, mac, vendor_mac, annotations, protocols, num_instances "
    "(tracked-device list; vendor_mac resolved from OUI)\n"
    "- known_users: host_ip, user_ (NOTE the trailing underscore, `user` is reserved), "
    "protocol, server_ip, annotations, num_instances (OBSERVED USERNAMES per host, seen "
    "over HTTP/RDP/SIP/etc. The strongest identity signal available: use for 'who is on "
    "this host' / 'which accounts did X use'. Treat as sensitive.)\n"
    "- known_domains: host_ip, domain, protocols, annotations, num_instances "
    "(domains a host announced, e.g. its DHCP domain; use for org/tenant attribution)\n"
    "- known_names: host_ip, hostname, protocols, num_instances "
    "(self-reported hostnames per host)\n"
    "- known_hosts: host_ip, long_conns, n_opened, n_closed, n_pending, annotations "
    "(per-host connection activity roll-up)\n"
    "- known_services: host_ip, port_num, protocol, service, software, app, "
    "num_conns_complete (LISTENING services per host: use for 'what is this box "
    "running' / exposed-surface questions)\n"
    "- known_certs: host_ip, hash, subject, issuer_subject, serial, port, protocol "
    "(certificates observed per host)\n"
    # One row per host per day, pre-joined from asset_classification + alerts +
    # known_* + uid_lookup. This is the fast path for "tell me about this host":
    # prefer it over hand-joining those sources.
    "- entity_context: ip, mac, vendor_mac, hostname, os_name, device_type, org_name, "
    "mgmt_tooling, randomized_mac, network_name, room_name, connections, mb_in, mb_out, "
    "first_seen, last_seen, id_confidence, alert_count, alert_count_all, "
    "high_alert_count, alert_types, top_alerts, last_alert_at, observed_users, "
    "user_count, user_protocols, service_count, services, listening_ports, "
    "observed_hostnames, announced_domains, session_count, log_type_count, log_types, "
    "org_confidence, org_reasons, org_tenant, org_tenant_sources, ai_tools, "
    "security_tools, owner_name, "
    "owner_name_source, owner_name_confidence, internal_domain, "
    "internal_domain_confidence, internal_domain_reasons, client_cert_issuer_org, "
    "client_cert_class, client_cert_subject_hash, client_cert_reasons, "
    "home_region, home_confidence, home_reasons, "
    "client_ja3, client_hassh, os_versions, domain_user, dt "
    # v4 selected a bare `confidence` here on the 2026-08-04 probe and died
    # COLUMN_NOT_FOUND. The list above is correct and complete; the trap is that
    # entity_context has SEVERAL confidence columns and none of them is the bare
    # name, while the neighbouring device_links does use the bare name. Naming the
    # near miss is cheaper than hoping the list is read closely enough.
    "(⚠ there is NO bare `confidence` column here: it is id_confidence, "
    "org_confidence, owner_name_confidence, internal_domain_confidence or "
    "home_confidence. Pick the one matching the field you are reporting.) "
    "(ONE ROW PER HOST PER DAY: identity + accounts + exposure + alert risk + session "
    "reach already joined together. Use this for 'what is this host / who is on it / "
    "is it risky' instead of joining asset_classification, alerts and known_* by hand. "
    "alert_count EXCLUDES informational ET INFO noise so it matches the live feed; "
    "alert_count_all is the raw total, much higher on DNS resolvers. To go from a "
    "session to its host: JOIN uid_lookup ul ON ul.orig_h = entity_context.ip. "
    "PROFILING COLUMNS: org_reasons and home_reasons carry '|'-delimited EVIDENCE "
    "for the attribution above them -- quote them so an analyst can audit the "
    "claim, and never state an org or region without them. home_region is a "
    "two-letter country code inferred from destination-traffic majority share, so "
    "treat it as a hint and always cite the percentage in home_reasons. client_ja3 "
    "and client_hassh are this host's dominant TLS/SSH client fingerprints -- the "
    "key for finding the SAME device on another IP. os_versions comes from the "
    "software log, domain_user from ntlm/kerberos and is populated for very few "
    "hosts. Any of these can be NULL; say 'not known' rather than guessing. "
    "ATTRIBUTION COLUMNS: owner_name is a first-name/hostname stem extracted from an "
    "mDNS instance name or a known_names hostname, emitted ONLY when that label is "
    "rare (few distinct IPs) because person-looking labels on many IPs are SHARED "
    "AirPlay/cast endpoints in session rooms -- always quote owner_name_source, which "
    "names the label and how many IPs carried it, and never present owner_name as a "
    "confirmed legal identity. org_tenant is the tenant label from an SSO/collab "
    "hostname (org_tenant_sources names which families agreed) and is the employer "
    "string; generic infra labels are already excluded. internal_domain is an "
    "employer's internal AD domain leaked by wpad/_ldap._tcp/_msdcs queries -- high "
    "confidence means the AD-specific records, medium means wpad only. "
    "client_cert_issuer_org/client_cert_class come from an mTLS client certificate "
    "this device was ENROLLED with, so they are enrolment evidence rather than an SNI "
    "guess. client_cert_subject_hash is a SHA-256 ONLY: the raw certificate subject "
    "is deliberately never stored because it contains a person's name, work email and "
    "employer in one string. Use the hash solely to match two sightings of the same "
    "certificate; never claim to know who it names. "
    "TOOLING COLUMNS: ai_tools is a ' | '-delimited count-ranked list of AI "
    "assistants this host made a TLS handshake to (ChatGPT, Claude, Copilot, Gemini, "
    "Cursor, Perplexity) and security_tools the same for security/management "
    "endpoints, each labelled with its CLASS as EDR:CrowdStrike | MDM:Intune | "
    "ZTNA:Zscaler | MFA:Okta | Vault:1Password. BOTH ARE OBSERVATIONS OF WHAT THE "
    "HOST CONTACTED, NOT PROOF OF WHAT IS INSTALLED: say 'contacted' or 'talks to', "
    "never 'is running' or 'is enrolled in'. A NULL means no such SNI was seen, "
    "which is not evidence the host is unmanaged or AI-free -- it may simply not "
    "have used it today. observed_hostnames is a comma list of names the host "
    "claimed, best source first (known_names, then its DHCP host_name, then its mDNS "
    "instance names). announced_domains likewise falls back to the mDNS `.local` "
    "SERVICE TYPES the host advertises (_rdlink, _companion-link, _airplay, "
    "_googlecast), which say what protocols it speaks and are the device-linking "
    "signal, not real DNS domains.)\n"
    # Device linking. The answer to "what ELSE does this person have", which no
    # single log can express -- it is a correlation across ssl/ssh/dns/dhcp.
    # v4 selected `hostname` here on the 2026-08-04 probe; device_links has only 9
    # columns and hostname is not one of them, even though the neighbouring
    # entity_context and asset_classification both have it.
    "- device_links: ip, mac, dt, owner_cluster_id, linked_ips, linked_macs, "
    "link_methods, link_evidence, confidence (these NINE are all of them: no "
    "hostname, no os_name, no device_type — join entity_context on ip for those) "
    "(ONE ROW PER HOST PER DAY: the other "
    "IPs believed to belong to the SAME PERSON. linked_ips is a ' | '-delimited "
    "list, capped at 12. link_methods is a comma list drawn from same_mac, "
    "same_ja3, same_hassh, same_rdfp, same_vpn_ja3, mdns_companion, shared_cast, "
    "shared_account. link_evidence is human-readable and should be quoted VERBATIM "
    "to the analyst rather than paraphrased -- it names the fingerprint and how "
    "many IPs shared it. owner_cluster_id is stable across a rebuild, so hosts "
    "sharing it are one cluster. confidence reflects the WEAKEST edge in the "
    "cluster, so 'high' means every link is solid. Use this for 'are these the "
    "same person', 'what other devices does this host's owner have', and to follow "
    "a laptop that roamed networks with a randomized MAC. It answers device "
    "linking that ja3 alone cannot: query it directly instead of self-joining ssl "
    "on ja3, which is expensive and will match stock browsers.)\n"
    # Authentication logs. Low volume today but the highest-signal data on the
    # network for credential attacks, so the model must know they exist.
    "- kerberos: uid, id_orig_h, id_resp_h, request_type, client, service, success, "
    "error_msg, cipher, renewable, client_cert_subject (KERBEROS AUTH: `client` is the "
    "principal, `success` is boolean-ish. Use for kerberoasting, AS-REP roasting, "
    "brute force, golden/silver ticket hunting.)\n"
    "- krb5_auth: uid, id_orig_h, id_resp_h, client, service, realm, error_code, "
    "cipher_req, ticket_hash (KERBEROS AS-REQ detail incl. error_code: repeated "
    "failures from one host is a password-spray or enumeration signal.)\n"
    "- ntlm: uid, id_orig_h, id_resp_h, username, hostname, domainname, "
    "server_dns_computer_name, success (NTLM AUTH: `username` and `domainname` are "
    "the account being used. Use for NTLM relay, spray, and legacy-auth findings.)\n"
    # Verified against Athena: DDL takes backticks, but the SELECT engine (Trino)
    # rejects them and wants DOUBLE QUOTES. Getting this wrong is not a soft
    # failure: a backticked SELECT is refused before it even runs.
    "- net_perf: uid, \"window\", trigger, host, domain, local_entity, total, crossings, "
    "max_val, sent_bytes, recv_bytes, reply_rate (network performance samples. "
    "WARNING: `window` is a RESERVED WORD. In a SELECT you MUST wrap it in DOUBLE "
    "QUOTES, not backticks: SELECT \"window\" FROM net_perf. A backticked SELECT is "
    "rejected outright.)\n"
    "- All tables have: ts (epoch bigint), ts_datetime (varchar), dt (varchar YYYY-MM-DD)\n\n"
    "TYPES & ENUMS:\n"
    "- alerts.severity is VARCHAR: 'critical','high','medium','low','informational','unknown'. "
    "Use `=` or `IN (...)`; NEVER `<`/`<=`/`>`/`>=`.\n"
    # Both of these were wrong and both produced a hard Athena failure. The
    # column is a STRING holding a digit, so an unquoted compare is
    # TYPE_MISMATCH: "Cannot apply operator: varchar = integer". Verified
    # against live prod. 'unknown' was missing from the severity list above for
    # the same reason: the enum was written from the dev catalog, not this one.
    "- suricata_corelight.alert_severity is a STRING holding a digit '1'-'4' (1=highest, "
    "4=informational). ALWAYS quote it: `alert_severity = '1'`, `alert_severity IN ('1','2')`. "
    "An unquoted `alert_severity = 1` or a range like `<= 2` fails with TYPE_MISMATCH.\n"
    # Same trap, different column, and v4 walked into it on the 2026-08-04 probe with
    # `id_resp_p IN (80,443)`. Verified against information_schema: every port column
    # in this catalog (conn, suricata_corelight, alerts) is varchar, not a number.
    "- EVERY PORT COLUMN IS ALSO A STRING: id_orig_p, id_resp_p, orig_p, resp_p are "
    "varchar. ALWAYS quote ports: `id_resp_p IN ('80','443')`, `id_resp_p = '22'`. "
    "An unquoted `id_resp_p IN (80,443)` fails with TYPE_MISMATCH. For numeric "
    "comparison (a port RANGE, or ORDER BY port) cast first: "
    "`CAST(id_resp_p AS integer) > 1024`.\n"
    "- For lateral movement / zone correlation, use suricata_corelight (has both-side zones). "
    "alerts only has orig_network_name.\n"
    "- For 'connections to Zoho/Google/AWS' style org queries, filter conn.remote_organization "
    "LIKE '%<org>%' (GeoIP enrichment).\n\n"
    "RULES:\n"
    # dt is the UTC calendar day of ts, but the analyst is standing in the NOC and
    # the venue is UTC-7. From 17:00 local onward the UTC date has already rolled,
    # so `dt = '<utc today>'` holds only the hours since 17:00 local. Measured on
    # prod at 19:33 local: 778,187 alerts against a true local-day 4,186,931, a 5.4x
    # undercount that succeeds silently and gets worse the earlier in the evening
    # you ask. Every same-day scope therefore takes the 2-partition prune plus
    # explicit ts bounds; the prune is coarse, the ts bounds are the real window.
    "1. ALWAYS include a date partition filter AND, for any window inside a day, "
    "explicit ts bounds. dt is a UTC calendar day but the analyst's clock is not "
    "UTC, so one local day spans TWO dt partitions. Pick by time scope:\n"
    "   - \"today\" / \"tonight\" / \"so far today\": "
    "`dt IN ('TODAY','YESTERDAY') AND ts >= DAY_START AND ts <= NOW`\n"
    "   - \"last N hours\" with N <= 24: "
    "`dt IN ('TODAY','YESTERDAY') AND ts >= <N-hour start> AND ts <= NOW`\n"
    "   - default / \"recent\" / no time mentioned / \"any\" / \"are there\": "
    "`dt IN ('TODAY','YESTERDAY') AND ts >= WINDOW_START AND ts <= NOW`\n"
    "   - \"yesterday\": "
    "`dt IN ('YESTERDAY','TODAY') AND ts >= YDAY_START AND ts <= YDAY_END`\n"
    "   - \"last N days\" / \"past week\" / \"last week\": "
    "`dt >= 'START_DATE' AND dt <= 'TODAY'` (whole-day granularity is fine here)\n"
    "   NEVER write a bare `dt = 'TODAY'` for a same-day question: it silently drops "
    "the evening hours that already rolled into the next UTC day.\n"
    "   TODAY, YESTERDAY, START_DATE and every epoch bound are computed for you in "
    "the user content. Use them verbatim; do not compute dates yourself.\n"
    "2. ALWAYS include LIMIT (max 200)\n"
    "3. Only SELECT queries — no DDL/DML\n"
    "4. Match column prefix to the table: `id_orig_h` on raw Zeek tables, `orig_h` on alerts/uid_lookup\n"
    "5. For aggregations on conn use CAST(orig_bytes AS bigint)\n"
    "6. NEVER use the name 'suricata' — the table is 'suricata_corelight'\n"
    # v3 emitted `FROM blackhat_pope_logs.ssl`, which is why this rule and the
    # _RE_DB_QUALIFIER strip both exist. v4 leaked a qualifier 0/22 times on the
    # 2026-08-04 probe and invented no database names, so the long explanation is
    # spending prompt budget on a fixed problem. One line is enough; the strip in
    # _sub_tokens stays as the actual enforcement.
    "6b. Use BARE table names: `FROM ssl`, never `FROM <database>.ssl`.\n"
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
    # Ports QUOTED here. They are varchar, and an exemplar beats a rule: the
    # unquoted version of this line is where v4 learned `id_resp_p IN (80,443)`.
    "    FROM conn WHERE dt=... "
    "AND id_resp_p IN ('22','3389','445','3306','5432','5900','1433','23')\n"
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
    "    LIMIT 200\n"
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
    "  Generate exactly THREE queries so identity, vendor, and behaviour all surface (the "
    "engine keeps only the first 3, so do NOT emit a 4th). Match the MAC exactly; do not "
    "lowercase or reformat it. Replace <oui> with the MAC's first 8 chars (e.g. '00:0c:29').\n"
    "  (1) asset_classification = the authoritative device inventory (real OUI-resolved "
    "vendor_mac like 'VMware'/'Apple, Inc.', plus device_type, brand, model, os_name). Match "
    "the exact MAC OR its OUI prefix in ONE query: an exact hit identifies THIS device; OUI "
    "siblings resolve the vendor even when this exact MAC is not inventoried (infra hosts "
    "often are not). Order exact-match first:\n"
    "    SELECT mac, vendor_mac, device_type, type_name, brand, os_name, confidence,\n"
    "           CASE WHEN mac='<mac>' THEN 1 ELSE 0 END AS exact\n"
    "    FROM asset_classification\n"
    "    WHERE dt IN ('TODAY','YESTERDAY') AND (mac='<mac>' OR substr(mac,1,8)='<oui>')\n"
    "      AND vendor_mac IS NOT NULL AND vendor_mac <> ''\n"
    "    GROUP BY mac, vendor_mac, device_type, type_name, brand, os_name, confidence\n"
    "    ORDER BY exact DESC, confidence DESC LIMIT 10\n"
    # Same nonexistent-column bug as the VERIFIED COLUMNS block above, and worse here:
    # an exemplar is copied, so this one line taught v4 to write id_orig_mac on every
    # MAC hunt. conn's MAC column is orig_l2_addr, and there is no vendor column on
    # conn to warn about.
    "  (2) conn = the MAC<->IP link and activity volume (orig_l2_addr is the MAC; conn "
    "has NO vendor column, so take the vendor from (1) or (3)):\n"
    "    SELECT id_orig_h, COUNT(*) AS connections\n"
    "    FROM conn WHERE dt IN ('TODAY','YESTERDAY') AND orig_l2_addr='<mac>'\n"
    "    GROUP BY id_orig_h ORDER BY connections DESC LIMIT 20\n"
    "  (3) known_devices for the self-reported hostname + vendor_mac (exact MAC or OUI):\n"
    "    SELECT mac, vendor_mac, host_ip, annotations FROM known_devices\n"
    "      WHERE dt IN ('TODAY','YESTERDAY') AND (mac='<mac>' OR substr(mac,1,8)='<oui>') LIMIT 10\n"
    "  Lead the answer with the EXACT-match device_type/os/vendor when present; otherwise "
    "state the vendor from the OUI-sibling rows (e.g. '00:0c:29 -> VMware'). NEVER report "
    "'vendor unknown' when (1) or (3) returned any vendor_mac for the OUI. Flag a "
    "locally-administered/randomized MAC (second hex digit 2,6,A,E).\n\n"
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
    # The LIMIT here is load-bearing. Every model tested (Gemini, AQLight,
    # Foundation-Sec) dropped LIMIT on the uid pivot when this exemplar omitted
    # it, copying the example over RULES #2. A concrete pattern beats a rule
    # stated once, so the patterns have to satisfy the rules themselves.
    "    FROM uid_lookup WHERE dt=... AND uid='<uid>' ORDER BY ts LIMIT 200\n"
    "  (uid_lookup uses orig_h / resp_h — NO id_ prefix.)\n\n"
    "* Vague / broad queries: widen to dt IN ('today','yesterday').\n\n"
    "CORRECTNESS CHECKS before you output SQL:\n"
    "1. Every WHERE on conn/dns/http/ssl/files/notice/suricata_corelight uses id_orig_h / id_resp_h.\n"
    "2. Every WHERE on alerts/uid_lookup/fuid_lookup uses orig_h / resp_h.\n"
    "2b. The SELECT list, GROUP BY and ORDER BY use the same prefixes as the WHERE.\n"
    "3. Date filter present, with ts bounds for any same-day scope. LIMIT present "
    "(max 200).\n"
    "4. Never use `severity < N` on alerts — severity is a string enum.\n\n"
    "Generate 1-3 SQL queries to answer the analyst's question. "
    "Return ONLY a JSON array of SQL strings:\n"
    '[\"SELECT ...\", \"SELECT ...\"]\n'
    "No markdown, no explanation."
)


async def generate_sql(
    query: str, iocs: dict[str, list[str]], today: str, lane: str | None = None,
) -> list[str]:
    """Use LLM to generate Athena SQL queries from natural language."""
    tracer = get_tracer()
    with tracer.start_as_current_span("athena_hunter.generate_sql") as span:
        span.set_attribute("query.length", len(query))
        span.set_attribute("query.text", query[:500])
        # CHAIN wrapper around the NL→SQL LLM call (LLM span auto-emitted as child).
        set_chain_span(span, input_value=query)

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
        # Real epoch bounds for a rolling 24h window. The dt partition list is a
        # whole-day PRUNE: a "last 24h" query spans two partitions (today+yesterday)
        # and, without a ts bound, returns up to ~48h of rows, double-counting on
        # real data (two capture days) and exactly doubling on the redated dev slice.
        # Bound BOTH ends: the upper bound (ts <= now) matters too, else FUTURE-stamped
        # rows leak in (the dev demo seeds today's 00:00-03:00 block, which is in the
        # future when queried at 01:00). Give the model both literals.
        _now = _dt.now(_tz.utc)
        _epoch_24h = int((_now - _td(hours=24)).timestamp())
        _epoch_now = int(_now.timestamp())
        # `today` is the EVENT-LOCAL calendar day (see athena_client.today_partition),
        # and a local day straddles two UTC dt partitions for most of the evening, so
        # the model has to be handed the local day's real epoch bounds rather than
        # left to infer them from a date string. Same for yesterday.
        _utc_today = _now.strftime("%Y-%m-%d")
        _day_start, _day_end = local_day_bounds(0)
        _yday_start, _yday_end = local_day_bounds(-1)
        _today_parts = ", ".join(repr(p) for p in local_day_partitions(0))
        _yday_parts = ", ".join(repr(p) for p in local_day_partitions(-1))

        user_content = (
            f"Partition dates you may use:\n"
            f"- today: {today}\n"
            f"- yesterday: {_yesterday}\n"
            f"- 7 days ago: {_week_ago}\n"
            f"- 30 days ago: {_month_ago}\n"
            f"- epoch bounds for exactly the last 24h (ts >= {_epoch_24h} AND ts <= {_epoch_now})\n"
            f"- epoch bounds for today so far (ts >= {_day_start} AND ts <= {_day_end})\n"
            f"- epoch bounds for all of yesterday (ts >= {_yday_start} AND ts <= {_yday_end})\n\n"
            f"Analyst query: {query}\n\n"
            f"{ioc_ctx}"
            "Build the date filter based on the analyst's time scope. The dt column is a "
            "UTC calendar day; the analyst's clock is NOT UTC, so a single local day spans "
            "two dt partitions. Never write a bare `dt = '" + today + "'` for a same-day "
            "question, it drops every hour that already rolled into the next UTC day.\n"
            f"- \"today\" / \"tonight\" / \"so far today\": `dt IN ({_today_parts}) "
            f"AND ts >= {_day_start} AND ts <= {_day_end}`\n"
            f"- \"yesterday\": `dt IN ({_yday_parts}) "
            f"AND ts >= {_yday_start} AND ts <= {_yday_end}`\n"
            f"- \"last N hours\" (N <= 24), \"recent\", or no time given: "
            f"`dt IN ({_today_parts}) AND ts >= {_epoch_24h} AND ts <= {_epoch_now}` "
            f"(for N < 24 keep the same prune and raise the lower bound by hand)\n"
            f"- multi-day ranges: `dt >= 'START' AND dt <= '{today}'`\n"
            "The partition prune is coarse (whole UTC days). The ts bounds are the real "
            "window, so ALWAYS include both of them for any sub-multi-day scope. Without "
            "them a 2-partition prune returns ~48h of rows and every COUNT is inflated; "
            "with a single partition instead, every COUNT is silently truncated."
        )

        # HYBRID: NL->SQL is the ONE step to route to a SQL-specialist (AQLight) when
        # configured, while synthesis below stays on LLM_PROVIDER (Gemini). SQLGEN_PROVIDER
        # is unset by default, so provider/model resolve to None and this behaves exactly
        # as before. See llm_client SQLGEN_PROVIDER + docs/llm/AQLight-integration.md.
        sqlgen_provider = SQLGEN_PROVIDER or None
        sqlgen_model = SQLGEN_MODEL or None
        span.set_attribute("sqlgen.provider", sqlgen_provider or (LLM_PROVIDER or "gemini"))
        if lane:
            span.set_attribute("lane", lane)
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
                provider=sqlgen_provider,
                model=sqlgen_model,
                # role="sqlgen" is what sends the LOCAL lane to AQLight rather than
                # Foundation-Sec. Note sqlgen_provider (SQLGEN_PROVIDER env) still
                # wins if an operator set it explicitly — lane is only a default.
                lane=lane,
                role="sqlgen",
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
            # STRIP any database qualifier, do not rewrite it. AQLight is fine-tuned
            # to emit a literal `<some_db>.<table>` prefix regardless of what the
            # prompt says, so this cannot be fixed in the prompt alone (RULES 6b
            # asks, this enforces). Dropping the qualifier is better than mapping it
            # to ATHENA_DATABASE: the execution context already names the database,
            # so a bare table is correct on every box, while a rewrite has to know
            # every stale name the weights might produce. The training-set name was
            # blackhat_pope_logs; prod is blackhatnoc_glue; the next one is unknown.
            # Anchored on FROM/JOIN so only a table position is rewritten. A bare
            # `\w+\.\w+` rule would also eat qualified COLUMNS (`f.uid`, `s.server_name`
            # in the files-join pattern), which would corrupt every joined query.
            s = _RE_DB_QUALIFIER.sub(r"\1\2", s)
            # Align orig_h/id_orig_h with the table. Runs AFTER the qualifier strip
            # so the table census sees a bare table name to match on. Single-table
            # queries only; see _fix_endpoint_prefix for why.
            s = _fix_endpoint_prefix(s)
            s = _fix_column_synonyms(s)
            return s

        # Inject date partition if missing.
        #
        # THE TEST IS FOR A dt PREDICATE, NOT THE LETTERS "dt". `"dt" not in sql.lower()`
        # is satisfied by any query that happens to contain the substring anywhere:
        # `SUM(orig_bytes) AS banDwidTh`, `service = 'dtls'`, `created_dt`, a table
        # aliased `dt`. Such a query skips injection entirely and then runs UNPARTITIONED
        # across the whole projected range (2026-04-01..12-31), so a question about
        # "today" silently returns all-time rows -- and it is the expensive kind of wrong,
        # scanning every partition. Require an actual `dt =` / `dt IN` / `dt >` predicate
        # at a word boundary.
        _DT_PREDICATE = re.compile(
            r"(?:^|[^a-z0-9_])dt\s*(?:=|<|>|!=|<>|\bIN\b|\bBETWEEN\b)", re.IGNORECASE)
        # The injected default is the 2-partition prune for the analyst's LOCAL day,
        # not `dt = '<today>'`. A local day straddles two UTC dt partitions for most
        # of the evening, so the single-partition form drops the hours that already
        # rolled over. The ts bounds get added by the safety net below (which skips
        # JOINs, where a bare `ts` is ambiguous).
        _local_prune = (
            f"dt IN ({', '.join(repr(p) for p in local_day_partitions(0))})"
        )
        validated = []
        for sql in queries[:3]:
            sql = _sub_tokens(sql)
            # The ts-less tables are DAILY SNAPSHOTS of one row per host, so two
            # partitions would return each host twice and there is no ts to bound it
            # back down with. `today` is already the analyst's local day, so a single
            # partition is the right answer for them.
            _prune = _local_prune if _query_supports_ts(sql) else f"dt = '{today}'"
            if not _DT_PREDICATE.search(sql):
                # Try to add dt filter
                if "WHERE" in sql.upper():
                    sql = re.sub(
                        r"(?i)(WHERE\s+)",
                        f"\\1{_prune} AND ",
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
                            f"{body[:m.start()]} WHERE {_prune}{body[m.start():]}"
                        )
                    else:
                        sql = f"{body} WHERE {_prune}"
            # Safety net for the count-doubling window bug: if the query prunes with
            # the 2-day partition form (dt IN ('a','b')) but the model omitted the ts
            # bound the prompt asked for, inject BOTH bounds so "last 24h" is truly 24h,
            # not ~48h. The upper bound (ts <= now) matters too: without it, future-
            # stamped rows leak in (dev demo seeds today's 00:00-03:00 block, in the
            # future at 01:00). Only when there is no ts predicate already and no JOIN
            # (a JOIN makes bare `ts` ambiguous across aliases; leave those to the
            # prompt). The dt tokens were already substituted to real YYYY-MM-DD above.
            #
            # It also has to catch the SINGLE-partition form. AQLight v4 answers
            # "last 6 hours" / "today" with `dt = '<one date>'` and never uses the
            # dt IN (..) form, so a net keyed only on dt IN () never fired for it.
            # A single UTC partition is not a local day: measured on prod at 19:33
            # local, `dt = '<utc today>'` gave 778,187 alerts where the local day
            # held 4,186,931. Promote a same-day single partition to the local pair
            # and bound it, keyed on the DATE VALUE so a genuine "yesterday" query
            # gets yesterday's window rather than today's.
            #
            # Skipped entirely for the ts-less host-keyed tables, and that is right
            # twice over: a bare `ts` there is COLUMN_NOT_FOUND, and those tables are
            # DAILY SNAPSHOTS of one row per host rather than a time series, so
            # spanning two partitions would duplicate every host. Their single
            # partition is already the analyst's local day, because `today` is now
            # local (see athena_client.today_partition).
            # A JOIN is handled, not skipped, when the dt predicate is ALIAS-QUALIFIED
            # (`a.dt = '...'`), because then `a.ts` is unambiguous too and the whole
            # reason for the old skip disappears. v4 writes the joins that way. An
            # UNQUALIFIED dt inside a join is still skipped: bare `ts` there is
            # AMBIGUOUS_NAME, and failing the query outright is worse than a
            # partition-granularity answer the analyst can see.
            low = sql.lower()
            has_ts_bound = re.search(r"\bts\s*>=", low) is not None
            has_join = " join " in low
            has_two_day_prune = re.search(r"dt\s+in\s*\(", low) is not None
            # Every same-day single-partition predicate, each with its optional alias.
            _singles = list(re.finditer(
                r"(?i)\b(?:([a-z_][a-z0-9_]*)\.)?dt\s*=\s*'(\d{4}-\d{2}-\d{2})'", sql))
            if not has_ts_bound and _query_supports_ts(sql):
                if has_two_day_prune and not has_join:
                    sql = re.sub(
                        r"(?i)(dt\s+IN\s*\([^)]*\))",
                        rf"\1 AND ts >= {_epoch_24h} AND ts <= {_epoch_now}",
                        sql,
                        count=1,
                    )
                elif _singles and not (has_join and not _singles[0].group(1)):
                    # Rewrite right-to-left so earlier match offsets stay valid. Each
                    # side of a join needs the widened partition pair or the join
                    # drops the rows that rolled into the next UTC day; the ts bound
                    # is added once, on the first predicate, since bounding either
                    # side of a uid join bounds the result.
                    _spans = []
                    for _m in _singles:
                        _alias, _d = _m.group(1), _m.group(2)
                        _q = f"{_alias}." if _alias else ""
                        if _d in (today, _utc_today):
                            _parts, _lo, _hi = local_day_partitions(0), _day_start, _day_end
                        elif _d == _yesterday:
                            _parts, _lo, _hi = local_day_partitions(-1), _yday_start, _yday_end
                        else:
                            # Some other explicit date. Leave the partition alone; the
                            # analyst named a UTC day and we have no local window for it.
                            continue
                        _spans.append((_m, _q, _parts, _lo, _hi))
                    for _i, (_m, _q, _parts, _lo, _hi) in reversed(list(enumerate(_spans))):
                        _repl = f"{_q}dt IN ({', '.join(repr(p) for p in _parts)})"
                        if _i == 0:
                            _repl += f" AND {_q}ts >= {_lo} AND {_q}ts <= {_hi}"
                        sql = sql[:_m.start()] + _repl + sql[_m.end():]
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


# Athena engine failures (COLUMN_NOT_FOUND, TABLE_NOT_FOUND) quote the fully
# catalog-qualified name back, e.g. "...Table 'awsdatacatalog.blackhatnoc_glue.conn'
# does not exist" or "Column 'id_orig_h' cannot be resolved". That raw string
# used to go straight into the LLM's analysis context (see llm_analyze), so a
# failed query could leak the Glue database/table names into the synthesized
# answer, and from there into the orchestrator's hint generator, which just
# echoes the answer text. Strip the catalog qualifier before the error is
# recorded so nothing downstream ever sees the schema name.
_RE_ENGINE_ERROR_CATALOG = re.compile(
    rf"\bawsdatacatalog\.{re.escape(ATHENA_DATABASE)}\.", re.IGNORECASE,
)
# Bare database name can also appear without the catalog prefix depending on
# the engine error shape; scrub it too rather than assuming one format.
_RE_ENGINE_ERROR_DBNAME = re.compile(
    rf"\b{re.escape(ATHENA_DATABASE)}\b", re.IGNORECASE,
)


def _scrub_engine_error(error: str) -> str:
    """Drop the catalog/database qualifier from a raw Athena engine error."""
    error = _RE_ENGINE_ERROR_CATALOG.sub("", error)
    return _RE_ENGINE_ERROR_DBNAME.sub("the data lake", error)


# ---------------------------------------------------------------------------
# Athena data gathering
# ---------------------------------------------------------------------------

async def gather_athena_context(
    iocs: list[str], query: str, lane: str | None = None,
) -> dict[str, Any]:
    """Generate SQL, execute against Athena, gather results."""
    tracer = get_tracer()
    with tracer.start_as_current_span("athena_hunter.gather_context") as span:
        classified = classify_iocs(iocs)
        today = today_partition()
        span.set_attribute("iocs.ips", len(classified["ips"]))
        span.set_attribute("iocs.domains", len(classified["domains"]))
        span.set_attribute("partition.date", today)
        set_chain_span(span, input_value=query)

        # Generate SQL via LLM
        sql_queries = await generate_sql(query, classified, today, lane=lane)
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

        # Execute all queries concurrently
        async def _run_one(i: int, sql: str) -> dict[str, Any]:
            with tracer.start_as_current_span(f"athena_hunter.execute_sql_{i}") as qspan:
                qspan.set_attribute("sql.query", sql[:500])
                # TOOL invocation against the Athena data lake — drives the
                # Agent → Tool INVOKES and Tool → Resource ACCESSES graph edges.
                set_tool_span(qspan, name="athena.query", input_value=sql)
                set_tool_resource(qspan, db_system="athena", db_name=ATHENA_DATABASE)
                try:
                    rows, meta = await execute_custom_sql(sql)
                    qspan.set_attribute("sql.row_count", len(rows))
                    qspan.set_attribute("output.value", f"{len(rows)} rows")
                    qspan.set_attribute("sql.execution_time_ms", meta["execution_time_ms"])
                    qspan.set_attribute("sql.data_scanned_mb", meta["data_scanned_mb"])

                    # A cache hit did no Athena work: recording its (replayed) cold
                    # timings and byte count again would double-count the original
                    # query and make the latency histogram and spend look worse than
                    # reality. Count the hit separately instead.
                    if meta.get("cached"):
                        _athena_cache_hit_counter.add(1)
                    else:
                        _athena_query_counter.add(1)
                        _athena_query_duration.record(meta["execution_time_ms"])
                        _athena_bytes_scanned.record(meta["data_scanned_bytes"])

                    logger.info(
                        "Athena query %d: %d rows, %dms, %.1fMB scanned",
                        i, len(rows), meta["execution_time_ms"], meta["data_scanned_mb"],
                    )
                    return {"sql": sql, "rows": rows, "meta": meta}
                except Exception as exc:
                    # Full, unscrubbed exception on the span/log for operators —
                    # only the copy that reaches the LLM (and from there the
                    # user-facing answer and hints) gets the schema name scrubbed.
                    qspan.set_attribute("error", str(exc))
                    logger.warning("Athena query %d failed: %s", i, exc)
                    return {"sql": sql, "error": _scrub_engine_error(str(exc))}

        results = await asyncio.gather(*[_run_one(i, sql) for i, sql in enumerate(sql_queries)])
        for res in results:
            if "error" in res:
                ctx["errors"].append({"sql": res["sql"], "error": res["error"]})
                continue
            sql = res["sql"]
            rows = res["rows"]
            meta = res["meta"]
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

        span.set_attribute("context.total_rows", ctx["total_rows"])
        span.set_attribute("context.total_queries", len(ctx["query_results"]))
        return ctx


# ---------------------------------------------------------------------------
# LLM analysis
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = (
    f"You are a SOC analyst at {EVENT_LABEL}. You queried Corelight/Zeek "
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
    "- Never say 'no results' when another query in the batch shows related activity.\n"
    "- A zero-row result only means nothing happened INSIDE THE QUERIED WINDOW, not that "
    "the host/entity is clean overall — the analyst may be looking at an old alert through "
    "a 'last hour' lens that no longer covers it. When you report a negative for a bounded "
    "time window (last hour/today/etc.), name that window in the answer (e.g. 'No activity "
    "from X in the last hour (16:00-17:00)') so a stale-window miss reads as a scoped "
    "result, not a clean bill of health.\n\n"
    "STYLE — FOLLOW EXACTLY:\n"
    "- Active voice, imperative. No hedging, no filler.\n"
    "- Skip 'Based on', 'It appears', 'The data shows', 'I analyzed'.\n"
    "- Skip meta-commentary about SQL ('The first query...', 'returned 0 rows'). "
    "Speak about the ACTIVITY, not the queries.\n"
    "- NEVER mention a database, table, schema, or catalog name (e.g. no "
    "'blackhatnoc_glue', no 'run SHOW TABLES', no table/column identifiers). If a "
    "query failed, say the lookup could not be completed — do not describe why in "
    "database terms.\n"
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
    "If EVERY query returned 0 rows, say so in one line and set confidence < 0.3. "
    "A query that FAILED (see Query Errors) is not the same as a query that ran "
    "and found 0 rows: a failure means the lookup was never actually performed, so "
    "do NOT phrase it as a negative finding ('no X found', 'none observed'). Say "
    "the lookup could not be completed and set confidence < 0.3. Only state a "
    "confident negative when a query actually SUCCEEDED with 0 rows."
)


async def llm_analyze(
    query: str, context: dict[str, Any], lane: str | None = None,
) -> tuple[str, float]:
    """Send Athena results to LLM for analysis."""
    tracer = get_tracer()
    with tracer.start_as_current_span("athena_hunter.llm_analyze") as span:
        set_chain_span(span, input_value=query)
        if lane:
            span.set_attribute("lane", lane)
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

        # Sanitize the ROWS, not just the question. Only `query` was scrubbed here,
        # so raw Athena output went to an external LLM (LLM_PROVIDER=gemini in prod)
        # carrying whatever the columns held. entity_context now surfaces
        # owner_name, observed_hostnames and observed_users — real attendee names off
        # a conference network — and ipscope's allowlist never got a say either, so an
        # out-of-scope address in a JOIN result egressed too. sanitize() applies both
        # scrubbers before the 6000-char cut, matching every other agent.
        context_str = sanitize(results_str[:6000])
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
                # Bound the thinking here for the same reason the SQL-gen call
                # above already does: `0` is clamped to -1 (UNBOUNDED dynamic) on
                # flash-lite and thinking shares max_output_tokens. Measured
                # against the live provider on 2026-08-05, this call did NOT
                # truncate at tb=0/mx=4096 — but it spent 3911 and 3742 output
                # tokens of its 4096 to emit ~2000 characters, i.e. ~95% of the
                # ceiling with under 200 tokens of margin. One longer result set
                # is all it takes to become the alert-triage failure, where a
                # missing confidence fence discards the answer entirely. Bounding
                # thinking also roughly HALVED usage (3911 -> 2124) for the same
                # output, so this is cheaper as well as safer.
                max_tokens=8192,
                temperature=0.1,
                thinking_budget=1024,
                # role="prose": on the local lane this is Foundation-Sec, NOT AQLight.
                lane=lane,
                role="prose",
            )
            span.set_attribute("llm.answer_length", len(answer))
        except RuntimeError as exc:
            span.set_attribute("error", str(exc))
            # User-facing text stays plain and short — a raw JSON dump of query
            # results reads as a broken product, not a real answer, and it is
            # internal detail the operator can't act on anyway.
            return ("There was an issue calling the model. Please try again.", 0.3)

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
            # Strip the fence out of the text the operator sees — it's parsed
            # into `confidence` above and the UI renders that as a bar; left in
            # place it shows up as a literal trailing code block.
            answer = answer[:m.start()].rstrip() + answer[m.end():]
        else:
            logger.warning("no confidence block in LLM answer, using low default")

        return answer, confidence


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="NOCgentic Athena Hunter", version="0.1.0")
instrument_fastapi_app(app)


class AnalyzeRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=5000)
    extracted_iocs: list[str] = Field(default_factory=list)
    # Which provider stack to run: "cloud" (Gemini), "local" (AQLight SQL +
    # Foundation-Sec prose), or None for the ambient LLM_PROVIDER config. The
    # orchestrator sets this when racing lanes; direct callers can omit it.
    lane: str | None = None


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
        set_agent_span(span, input_value=req.query, name="athena-hunter")
        if req.lane:
            span.set_attribute("lane", req.lane)

        start = time.monotonic()
        logger.info(
            "analyze query_len=%d iocs=%d lane=%s",
            len(req.query), len(req.extracted_iocs), req.lane or "-",
        )

        # Gather data via Athena
        context = await gather_athena_context(req.extracted_iocs, req.query, lane=req.lane)

        # LLM analysis
        answer, confidence = await llm_analyze(req.query, context, lane=req.lane)

        elapsed = time.monotonic() - start
        elapsed_ms = round(elapsed * 1000, 1)
        span.set_attribute("response.confidence", confidence)
        span.set_attribute("response.elapsed_ms", elapsed_ms)
        span.set_attribute("response.length", len(answer))
        span.set_attribute("response.text", (answer or "")[:2000])
        span.set_attribute("athena.total_rows", context["total_rows"])
        span.set_attribute("athena.total_query_time_ms", context["total_query_time_ms"])
        set_agent_span(span, output_value=answer, name="athena-hunter")
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
                    "row_count": qr["row_count"],
                    "time_ms": qr["execution_time_ms"],
                    "scanned_mb": qr["data_scanned_mb"],
                    # The actual rows Athena returned, not just the count — the
                    # UI's "Raw" panel shows these, capped the same way the LLM
                    # context is (see gather_athena_context: rows[:100]).
                    "sample_rows": qr["rows"],
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
# "4" -> informational matches both the source of truth and the Athena `alerts`
# view's own CASE. It is 83% of live suricata rows, so treating it as an
# unparseable value scored it as medium and floated the noisiest severity in the
# data to the top of the feed.
_NUM_SEV = {"1": "high", "2": "medium", "3": "low", "4": "informational"}
_WORD_SEV = {
    "informational (default)": "informational",
    "notification":            "low",
    "error":                   "high",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "unknown", "low", "informational"}


def _normalize_severity(raw: str | None) -> str:
    # Behaviorally identical to alert-triage._norm_sev for all shared inputs:
    # numeric 1/2/3/4 -> high/medium/low/informational; recognized words pass
    # through; the word aliases above are folded; and any unrecognized / blank /
    # None / 5+ value returns "unknown" (NOT "low") so it stays visible instead
    # of being buried.
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
    resp_h = row.get("resp_h") or ""
    network = (row.get("orig_network_name") or "").strip()

    def _parse_port(raw: str | None) -> int | None:
        if raw is None or raw == "":
            return None
        try:
            p = int(raw)
        except (ValueError, TypeError):
            return None
        return p if 0 <= p <= 65535 else None

    src_port = _parse_port(row.get("orig_p"))
    dst_port = _parse_port(row.get("resp_p"))

    # Identity is derived from the RAW host, before redaction, then hashed. Using
    # the redacted value would collapse every out-of-scope host onto one id, and
    # the UI drops duplicate ids (index.html dedups on data-id), silently losing
    # alerts. Using the raw value would re-leak the address, since the id is
    # written to a data-id DOM attribute. A hash keeps it unique and opaque.
    host_key = (
        hashlib.sha256(orig_h.encode()).hexdigest()[:12]
        if orig_h and not ipscope.is_in_scope(orig_h)
        else orig_h
    )

    # The alert feed reaches the browser via web-server's alertCache, which does
    # NOT pass through the orchestrator's output sanitizer — so scope-redact here
    # or out-of-scope addresses ship straight to the UI.
    description = credscrub.scrub_secrets(ipscope.redact_text(description))
    if orig_h and not ipscope.is_in_scope(orig_h):
        orig_h = ipscope.OUT_OF_SCOPE_PLACEHOLDER
    if resp_h and not ipscope.is_in_scope(resp_h):
        resp_h = ipscope.OUT_OF_SCOPE_PLACEHOLDER
    if network:
        network = credscrub.scrub_secrets(ipscope.redact_text(network))
    if uid:
        uid = credscrub.scrub_secrets(ipscope.redact_text(uid))
    alert_id = (
        f"{alert_name}|{host_key}|{ts_raw}"
        if alert_name
        else uid or f"alrt-{hash((ts_raw, description)) & 0xFFFFFFFF:08x}"
    )

    out: dict[str, Any] = {
        "id": alert_id,
        "timestamp": ts_raw,
        "severity": _normalize_severity(row.get("severity")),
        "source": (row.get("alert_type") or "corelight").strip().lower() or "corelight",
        "description": description[:500],
        "srcIp": orig_h or None,
        "dstIp": resp_h or None,
    }
    if src_port is not None:
        out["srcPort"] = src_port
    if dst_port is not None:
        out["dstPort"] = dst_port
    if uid:
        out["uid"] = uid
    if network:
        out["network"] = network
    if occ > 0:
        out["occurrences"] = occ
    return out


def _row_touches_conference_network(row: dict[str, str]) -> bool:
    """True if either endpoint of this alert row is inside a conference subnet.

    Separate from ipscope.row_in_scope: that function is a redaction gate ("is
    it safe to display this row's addresses verbatim") and passes public
    internet addresses. This is the feed's scope gate ("is the venue actually
    on one side of this event") — an alert entirely between two outside
    addresses is not a Black Hat NOC finding, whatever its severity.
    """
    return ipscope.is_conference_network(row.get("orig_h") or "") or ipscope.is_conference_network(
        row.get("resp_h") or ""
    )


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
        set_tool_span(span, name="athena.query", parameters={"hours": hours, "limit": limit})
        set_tool_resource(span, db_system="athena", db_name=ATHENA_DATABASE)

        dt = date_filter(hours)
        # Exclude noisy ET INFO signatures — they're informational, not
        # actionable, and flood the feed with duplicates. Same reasoning drops
        # 'informational' severity outright (Suricata sev 4, 83% of live rows).
        #
        # SSL::Invalid_Server_Cert is excluded by NAME, not by detail-text
        # pattern-matching. A first pass matched only "self signed", a second
        # added "self-signed" for the hyphenated live wording, and the very next
        # live pull was still 8 of 9 alerts under this same note — this time
        # "unable to get local issuer certificate" (an incomplete cert chain,
        # common on captive/guest WiFi). Every validation-failure reason under
        # this one note is the same noise on this network: chasing wording
        # variants one string at a time is a losing game against Zeek's actual
        # error-message space. Drop the whole note.
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
            ARBITRARY(orig_p) AS orig_p,
            ARBITRARY(resp_p) AS resp_p,
            ARBITRARY(orig_network_name) AS orig_network_name,
            COUNT(*) AS occurrences
        FROM alerts
        WHERE {dt}
          AND alert_name IS NOT NULL
          AND UPPER(alert_name) NOT LIKE 'ET INFO%'
          AND UPPER(alert_name) NOT LIKE 'ETPRO INFO%'
          AND severity <> 'informational'
          AND alert_name <> 'SSL::Invalid_Server_Cert'
        GROUP BY alert_name, alert_type, severity, orig_h
        ORDER BY MAX(ts) DESC
        LIMIT {limit}
        """

        try:
            rows, meta = await execute_custom_sql(sql)
            # Scope filter: the feed is a Black Hat NOC view, not a general Athena
            # dump. An alert with neither endpoint inside a conference subnet
            # (e.g. two internet hosts correlated via a lookup join) is dropped
            # rather than shown with a redacted host the analyst cannot act on.
            rows = [r for r in rows if _row_touches_conference_network(r)]
            alerts = [_athena_row_to_alert(r) for r in rows]
            span.set_attribute("alerts.count", len(alerts))
            span.set_attribute("athena.execution_time_ms", meta.get("execution_time_ms", 0))
            if meta.get("cached"):
                _athena_cache_hit_counter.add(1)
            else:
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
