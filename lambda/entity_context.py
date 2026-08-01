"""One row per host per day: everything known about an entity, pre-joined.

`uid_lookup` answers "what did this session do". This answers "what IS this host",
so an analyst pivoting off a session gets identity, accounts, exposure and risk in
a single join instead of six.

The pivot it enables:

    uid -> uid_lookup -> orig_h -> entity_context

That second hop exists because the `known_*` inventory tables do NOT carry the
session `uid`. They carry a `kuid`, which appears in no session log and is per
observation rather than per host (one host had 3 kuids across 4 rows), so
`host_ip` is the only real join key.

AGGREGATE FIRST, NEVER JOIN RAW. Measured on live data: `alerts` has up to 11,054
rows for a single host and `known_services` up to 4,433, so a naive
alerts x services LEFT JOIN produced 11,281,985 rows for ONE host. Every source
here collapses to one row per host before anything is joined.
"""

from __future__ import annotations

# Alert-name prefixes that are informational telemetry, not detections. The live
# feed already excludes these (agents/athena-hunter/main.py::alerts_recent), and
# the counts here must agree with what the analyst sees in the sidebar. Without
# this, DNS resolvers dominate: 10.220.199.121 alone logs 11,032 alerts, all of
# them "ET INFO Observed DNS Query".
_NOISE_PREFIXES: tuple[str, ...] = ("ET INFO", "ETPRO INFO")

# How many distinct values to carry in the top-N summary columns. Enough to be
# useful in an answer, small enough that a busy host does not blow up the row.
_TOP_N = 6


def _noise_filter(column: str = "alert_name") -> str:
    return " AND ".join(
        f"UPPER({column}) NOT LIKE '{p}%'" for p in _NOISE_PREFIXES
    )


def build_entity_context_sql(database: str, date_str: str, tables: dict[str, set]) -> str | None:
    """One row per host_ip for `date_str`, merging every entity-shaped source.

    Uses FULL OUTER JOIN rather than starting from one spine: a host can appear in
    the inventory without alerting, or alert without ever being inventoried, and
    both are worth seeing. Starting from `alerts` would hide quiet hosts; starting
    from `asset_classification` would hide alerting hosts it never classified.

    Returns None if nothing joinable exists, so a partial catalog skips the step
    rather than writing a table of nulls.
    """
    have = lambda t: t in tables  # noqa: E731

    ctes: list[str] = []
    # (cte alias, ip column) in the order they get folded together
    parts: list[tuple[str, str]] = []

    if have("asset_classification") or have("asset_classification_" + date_str.replace("-", "_")):
        # The stable view is rebuilt to point at today's partition, so read that.
        ctes.append(f"""ac AS (
  SELECT ip,
         ARBITRARY(mac) mac, ARBITRARY(vendor_mac) vendor_mac,
         ARBITRARY(hostname) hostname, ARBITRARY(os_name) os_name,
         ARBITRARY(device_type) device_type, ARBITRARY(org_name) org_name,
         ARBITRARY(mgmt_tooling) mgmt_tooling,
         ARBITRARY(randomized_mac) randomized_mac,
         ARBITRARY(network_name) network_name, ARBITRARY(room_name) room_name,
         SUM(connections) connections, SUM(mb_in) mb_in, SUM(mb_out) mb_out,
         MIN(first_seen) first_seen, MAX(last_seen) last_seen,
         ARBITRARY(confidence) id_confidence
  FROM {database}.asset_classification
  GROUP BY ip
)""")
        parts.append(("ac", "ip"))

    if have("alerts") or have("suricata_corelight"):
        # Two counts on purpose. `alert_count` excludes informational noise so it
        # matches the sidebar; `alert_count_all` keeps the raw total so a DNS
        # resolver's volume is still visible if someone asks for it.
        ctes.append(f"""al AS (
  SELECT orig_h ip,
         COUNT(*) alert_count_all,
         SUM(CASE WHEN {_noise_filter()} THEN 1 ELSE 0 END) alert_count,
         SUM(CASE WHEN severity IN ('critical','high') AND {_noise_filter()}
                  THEN 1 ELSE 0 END) high_alert_count,
         ARRAY_JOIN(SLICE(ARRAY_AGG(DISTINCT alert_type), 1, {_TOP_N}), ',') alert_types,
         ARRAY_JOIN(SLICE(ARRAY_AGG(DISTINCT CASE WHEN {_noise_filter()}
                    THEN alert_name END), 1, {_TOP_N}), ' | ') top_alerts,
         MAX(ts_datetime) last_alert_at
  FROM {database}.alerts
  WHERE dt = '{date_str}' AND orig_h IS NOT NULL
  GROUP BY orig_h
)""")
        parts.append(("al", "ip"))

    if have("known_users"):
        # Observed account names. The highest-value identity signal in the data and
        # the most sensitive: an analyst asking "who is on this host" gets a real
        # answer. Sparse by nature (6 hosts today), so expect nulls.
        ctes.append(f"""ku AS (
  SELECT host_ip ip,
         ARRAY_JOIN(SLICE(ARRAY_AGG(DISTINCT user_), 1, {_TOP_N}), ',') observed_users,
         COUNT(DISTINCT user_) user_count,
         ARRAY_JOIN(SLICE(ARRAY_AGG(DISTINCT protocol), 1, {_TOP_N}), ',') user_protocols
  FROM {database}.known_users
  WHERE dt = '{date_str}' AND host_ip IS NOT NULL AND user_ IS NOT NULL
  GROUP BY host_ip
)""")
        parts.append(("ku", "ip"))

    if have("known_services"):
        ctes.append(f"""ks AS (
  SELECT host_ip ip,
         COUNT(DISTINCT service) service_count,
         ARRAY_JOIN(SLICE(ARRAY_AGG(DISTINCT service), 1, {_TOP_N}), ',') services,
         ARRAY_JOIN(SLICE(ARRAY_AGG(DISTINCT CAST(port_num AS VARCHAR)), 1, {_TOP_N}), ',') listening_ports
  FROM {database}.known_services
  WHERE dt = '{date_str}' AND host_ip IS NOT NULL AND service IS NOT NULL
  GROUP BY host_ip
)""")
        parts.append(("ks", "ip"))

    if have("known_names"):
        ctes.append(f"""kn AS (
  SELECT host_ip ip,
         ARRAY_JOIN(SLICE(ARRAY_AGG(DISTINCT hostname), 1, {_TOP_N}), ',') observed_hostnames
  FROM {database}.known_names
  WHERE dt = '{date_str}' AND host_ip IS NOT NULL AND hostname IS NOT NULL
  GROUP BY host_ip
)""")
        parts.append(("kn", "ip"))

    if have("known_domains"):
        ctes.append(f"""kdom AS (
  SELECT host_ip ip,
         ARRAY_JOIN(SLICE(ARRAY_AGG(DISTINCT domain), 1, {_TOP_N}), ',') announced_domains
  FROM {database}.known_domains
  WHERE dt = '{date_str}' AND host_ip IS NOT NULL AND domain IS NOT NULL
  GROUP BY host_ip
)""")
        parts.append(("kdom", "ip"))

    if have("uid_lookup") or have("conn"):
        # Session reach: how much of the network's activity this host accounts for,
        # and which log types it shows up in. This is the column that makes the
        # uid -> entity pivot worth doing in one query.
        ctes.append(f"""ul AS (
  SELECT orig_h ip,
         COUNT(DISTINCT uid) session_count,
         COUNT(DISTINCT log_type) log_type_count,
         ARRAY_JOIN(SLICE(ARRAY_AGG(DISTINCT log_type), 1, {_TOP_N + 4}), ',') log_types
  FROM {database}.uid_lookup
  WHERE dt = '{date_str}' AND orig_h IS NOT NULL
  GROUP BY orig_h
)""")
        parts.append(("ul", "ip"))

    if not parts:
        return None

    # FULL OUTER so a host present in any single source still gets a row.
    first = parts[0][0]
    coalesce_chain = ", ".join(f"{a}.ip" for a, _ in parts)
    ip_expr = f"COALESCE({coalesce_chain})" if len(parts) > 1 else f"{first}.ip"

    joins = ""
    for alias, _ in parts[1:]:
        prior = ", ".join(f"{a}.ip" for a, _ in parts[:parts.index((alias, "ip"))])
        joins += f"\nFULL OUTER JOIN {alias} ON {alias}.ip = COALESCE({prior})"

    select_cols = [f"  {ip_expr} ip"]
    known_aliases = {a for a, _ in parts}
    for alias, cols in (
        ("ac", ["mac", "vendor_mac", "hostname", "os_name", "device_type", "org_name",
                "mgmt_tooling", "randomized_mac", "network_name", "room_name",
                "connections", "mb_in", "mb_out", "first_seen", "last_seen",
                "id_confidence"]),
        ("al", ["alert_count", "alert_count_all", "high_alert_count", "alert_types",
                "top_alerts", "last_alert_at"]),
        ("ku", ["observed_users", "user_count", "user_protocols"]),
        ("ks", ["service_count", "services", "listening_ports"]),
        ("kn", ["observed_hostnames"]),
        ("kdom", ["announced_domains"]),
        ("ul", ["session_count", "log_type_count", "log_types"]),
    ):
        for c in cols:
            select_cols.append(f"  {alias}.{c} {c}" if alias in known_aliases
                               else f"  CAST(NULL AS VARCHAR) {c}")
    select_cols.append(f"  '{date_str}' dt")

    return ("WITH " + ",\n".join(ctes) + "\nSELECT\n" + ",\n".join(select_cols)
            + f"\nFROM {first}" + joins)


def table_name(date_str: str) -> str:
    return f"entity_context_{date_str.replace('-', '_')}"


def build_ctas(database: str, date_str: str, tables: dict[str, set]) -> str | None:
    """CREATE TABLE AS for one partition.

    Materialized, not a view: this is seven aggregations over the largest tables in
    the catalog, so evaluating it per query would be slow and expensive. The hourly
    rebuild keeps it current and reads stay cheap.
    """
    body = build_entity_context_sql(database, date_str, tables)
    if not body:
        return None
    return f"CREATE TABLE {database}.{table_name(date_str)} AS\n{body}"
