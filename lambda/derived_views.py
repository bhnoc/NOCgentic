"""Discovery-driven derived Athena views.

The raw per-log-type tables are built by the refresh Lambda. These three views sit
on top of them and are what the agents actually query:

    alerts       every security signal, one shape, whatever produced it
    uid_lookup   every log line for a session UID, across all log types
    fuid_lookup  every log line for a file UID

They are rebuilt from GLUE INTROSPECTION on every run rather than from a hardcoded
list of tables. That matters because Corelight only writes a log type once it has
actually seen that traffic: `rdp` does not exist in the catalog today, and a
hand-maintained UNION would silently keep excluding it after it shows up. Anything
new that carries a `uid` joins uid_lookup on the next run with no code change.

The previous hand-made views in the other account had drifted badly for exactly
this reason: uid_lookup covered 9 tables when 37 carried a uid, and fuid_lookup
covered 1 when 8 did.
"""

from __future__ import annotations

import re

# Alert sources, in the order we want them to appear. Each entry maps a source
# table onto the common alert shape. `where` is an extra predicate for tables
# that carry a mix of alerting and non-alerting rows.
#
# Severity vocabulary must match the app's _normalize_severity valid set:
# critical | high | medium | low | informational | unknown. Note 'info' is NOT
# in it: the app maps 'info' to 'unknown', which would mislabel every anomaly
# row. Verified against agents/athena-hunter/main.py::_normalize_severity.
_IDENT_RE = re.compile(r"\b[a-z_][a-z0-9_]*\b")
# Tokens that appear in override expressions but are not column names.
_SQL_KEYWORDS = frozenset({
    "regexp_extract", "coalesce", "concat", "cast", "null", "as", "varchar",
    "case", "when", "then", "else", "end", "try_cast", "double", "false", "true",
})

ALERT_SOURCES: tuple[dict, ...] = (
    {
        "table": "suricata_corelight",
        "alert_type": "suricata",
        "name": "alert_signature",
        "detail": "alert_category",
        # Suricata severity is an int, 1 = most severe. Recovered from the
        # original view definition rather than guessed.
        "severity": (
            "CASE CAST(alert_severity AS INT) "
            "WHEN 1 THEN 'high' WHEN 2 THEN 'medium' WHEN 3 THEN 'low' "
            "ELSE 'informational' END"
        ),
    },
    {
        "table": "notice",
        "alert_type": "notice",
        "name": "note",
        "detail": "msg",
        # NORMALIZED, not passed through. This was the only arm that shipped its
        # source's raw string, and Zeek notice does not use the app's vocabulary:
        # measured in alerts on dt=2026-08-01, severity held 'error' (2,965 rows),
        # 'informational (default)' (239) and 'notification' (22). None of them are in
        # the closed set, so entity_context's `severity IN ('critical','high')` skipped
        # every one, query_alerts(severity='high') missed them, and an LLM writing SQL
        # against the documented vocabulary could not find them either -- 2,965 real
        # high-severity notices invisible to every consumer that filtered correctly.
        #
        # The mapping mirrors alert-triage._norm_sev / athena-hunter._WORD_SEV, which
        # are the source of truth. Anything unrecognised becomes 'unknown' rather than
        # 'low', so a new Zeek severity stays VISIBLE instead of being buried.
        "severity": (
            "CASE LOWER(TRIM(COALESCE(severity_name, ''))) "
            "WHEN 'error' THEN 'high' "
            "WHEN 'notification' THEN 'low' "
            "WHEN 'informational (default)' THEN 'informational' "
            "WHEN 'critical' THEN 'critical' WHEN 'high' THEN 'high' "
            "WHEN 'medium' THEN 'medium' WHEN 'low' THEN 'low' "
            "WHEN 'informational' THEN 'informational' "
            "ELSE 'unknown' END"
        ),
    },
    {
        "table": "corelight_ml_results",
        "alert_type": "ml",
        "name": "predicted_tag_name",
        "detail": "CONCAT('domain=', COALESCE(domain, ''), ' nearest_ref=', COALESCE(nearest_ref_domain, ''))",
        # The model emits a probability, not a label. Bucket it so ML findings
        # sort alongside rule-based ones instead of always landing in 'unknown'.
        "severity": (
            "CASE WHEN TRY_CAST(predicted_probability AS DOUBLE) >= 0.9 THEN 'high' "
            "WHEN TRY_CAST(predicted_probability AS DOUBLE) >= 0.7 THEN 'medium' "
            "WHEN TRY_CAST(predicted_probability AS DOUBLE) IS NOT NULL THEN 'low' "
            "ELSE 'unknown' END"
        ),
        "where": "predicted_tag_name IS NOT NULL",
    },
    {
        "table": "yara_corelight",
        "alert_type": "yara",
        "name": "match_rule",
        "detail": "CONCAT('file=', COALESCE(file_name, ''), ' sha256=', COALESCE(sha256, ''))",
        # A YARA hit is a positive malware-signature match on a file: treat as
        # high, not informational.
        "severity": "'high'",
        "where": "match_rule IS NOT NULL",
    },
    {
        # Corelight's anomaly detection log (LogScale `_path: anomaly`, so the
        # refresh Lambda lands it as table `anomaly`).
        #
        # NOT PRESENT YET as of 2026-08-01: the detector baselines the network
        # before it emits anything and the show just started. Pre-wired so it folds
        # itself into `alerts` on the first hourly run after the table appears, with
        # no code change mid-show. build_alerts_sql skips a source whose table is
        # absent, so this is a no-op until then.
        #
        # Schema confirmed against a real record from a sibling sensor, NOT guessed.
        # It is shaped unlike every other alert source, which drove three choices:
        #
        #  * There is no id_orig_h / id_resp_h. The subject is `entity` (a subnet
        #    CIDR like "172.27.0.0/24") and `original_entity` (a host CIDR like
        #    "172.27.0.137/32"). We strip the /NN off original_entity for orig_h,
        #    because the scope allowlist parses bare addresses: is_in_scope
        #    ("10.220.40.7/32") is False even for an in-scope host, so passing the
        #    CIDR through would silently redact every anomaly row.
        #  * item_score is a 0-1 confidence, so it buckets like the ML source.
        #  * item_assoc_entities is a ~400-element array of mostly out-of-scope
        #    CIDRs. It is deliberately NOT projected: row_in_scope scans every
        #    value on a row, so including it would drop 100% of anomaly rows.
        "table": "anomaly",
        "alert_type": "anomaly",
        "name": "use_case",
        # use_case_description is the human sentence ("Anomalous HTTP User Agent
        # Family Identified on Subnet"); item is the offending value ("Wget").
        "detail": (
            "CONCAT(COALESCE(use_case_description, ''), "
            "' | observed=', COALESCE(item, ''), "
            "' | subnet=', COALESCE(entity, ''))"
        ),
        "severity": (
            "CASE WHEN TRY_CAST(item_score AS DOUBLE) >= 0.9 THEN 'high' "
            "WHEN TRY_CAST(item_score AS DOUBLE) >= 0.7 THEN 'medium' "
            "WHEN TRY_CAST(item_score AS DOUBLE) IS NOT NULL THEN 'low' "
            "ELSE 'unknown' END"
        ),
        # `ignorable` is the sensor's own "this is benign" flag. Honour it.
        "where": "use_case IS NOT NULL AND COALESCE(ignorable, false) = false",
        # Non-standard host columns: strip the CIDR suffix so scope checks work.
        "orig_h_expr": "REGEXP_EXTRACT(original_entity, '^([^/]+)')",
        "resp_h_expr": "CAST(NULL AS VARCHAR)",
    },

    # NOTE: `weird` (Zeek protocol-anomaly telemetry) is deliberately NOT an alert
    # source, and is not the same thing as the `anomaly` log above. It is 4.4M
    # rows/day against suricata's 221k, a 20:1 ratio that buries every real IDS hit
    # in a recency-ordered feed, and it is diagnostic telemetry rather than a
    # detection. It stays queryable directly and via uid_lookup.
)

# Columns every alert row exposes. Source tables use the Zeek `id_` prefix; the
# view strips it, which is the convention the agents' prompts already document.
_ALERT_COLUMNS: tuple[tuple[str, str], ...] = (
    ("ts_datetime", "ts_datetime"),
    ("ts", "ts"),
    ("uid", "uid"),
    ("id_orig_h", "orig_h"),
    ("id_orig_p", "orig_p"),
    ("id_resp_h", "resp_h"),
    ("id_resp_p", "resp_p"),
    ("id_orig_network_name", "orig_network_name"),
)

# uid_lookup / fuid_lookup carry only the correlation keys plus enough context to
# be useful without a join back to the source.
_LOOKUP_COLUMNS: tuple[tuple[str, str], ...] = (
    ("ts", "ts"),
    ("ts_datetime", "ts_datetime"),
    ("id_orig_h", "orig_h"),
    ("id_resp_h", "resp_h"),
    ("id_orig_network_name", "orig_network_name"),
)

# Tables to never fold into a lookup view. These are metrics/operational rollups,
# not session records; including them inflates row counts without adding context.
_LOOKUP_EXCLUDE: frozenset[str] = frozenset({
    "corelight_ml_metrics",
    "corelight_overall_capture_loss",
    "suricata_stats",
    "reporter",
    "perf",
    "loaded_scripts_polaris",
})


def _col_or_null(available: set[str], col: str, cast: str = "VARCHAR") -> str:
    """A source may not have every column. Emit NULL so the UNION still lines up.

    Corelight's schema varies by log type and by sensor version, so assuming a
    column exists is how a whole view ends up failing to build.
    """
    return col if col in available else f"CAST(NULL AS {cast})"


def build_alerts_sql(database: str, tables: dict[str, set[str]]) -> str | None:
    """UNION ALL every alert-producing source into one shape.

    Skips a configured source whose table is absent or which lacks the column
    carrying its alert name, so a missing sensor feature degrades that one branch
    instead of breaking the view.
    """
    branches: list[str] = []
    for src in ALERT_SOURCES:
        name = src["table"]
        cols = tables.get(name)
        if cols is None:
            continue
        # `name`/`detail`/`severity` may be expressions, not bare columns. Only
        # gate on a bare column we can actually verify.
        key = src["name"]
        if key.isidentifier() and key not in cols:
            continue
        # An override expression referencing a column the source lacks would make
        # the whole view fail to build, so verify those too.
        missing_override = False
        for alias in (a for _, a in _ALERT_COLUMNS):
            expr = src.get(f"{alias}_expr")
            if expr:
                for token in _IDENT_RE.findall(expr):
                    if token in _SQL_KEYWORDS or token in cols:
                        continue
                    missing_override = True
                    break
        if missing_override:
            continue

        # A source may carry its host in a non-standard column (the anomaly log
        # uses CIDR-shaped `original_entity` instead of id_orig_h). An explicit
        # <alias>_expr overrides the default column lookup.
        select = []
        for src_col, alias in _ALERT_COLUMNS:
            override = src.get(f"{alias}_expr")
            select.append(f"  {override} AS {alias}" if override
                          else f"  {_col_or_null(cols, src_col)} AS {alias}")
        select.append(f"  '{src['alert_type']}' AS alert_type")
        select.append(f"  {src['name']} AS alert_name")
        select.append(f"  {src['detail']} AS alert_detail")
        select.append(f"  {src['severity']} AS severity")
        select.append("  dt AS dt")
        branch = "SELECT\n" + ",\n".join(select) + f"\nFROM {database}.{name}"
        if src.get("where"):
            branch += f"\nWHERE {src['where']}"
        branches.append(branch)

    if not branches:
        return None
    return "\nUNION ALL\n".join(branches)


def _build_lookup_sql(database: str, tables: dict[str, set[str]], key: str) -> str | None:
    """UNION every table carrying `key` into a correlation index.

    This is the discovery step: membership comes from the catalog, not a list.
    """
    branches: list[str] = []
    for name in sorted(tables):
        if name in _LOOKUP_EXCLUDE:
            continue
        cols = tables[name]
        if key not in cols or "dt" not in cols:
            continue
        select = [f"  {key} AS {key}", f"  '{name}' AS log_type"]
        select += [f"  {_col_or_null(cols, s)} AS {a}" for s, a in _LOOKUP_COLUMNS]
        select.append("  dt AS dt")
        branches.append(
            "SELECT\n" + ",\n".join(select)
            + f"\nFROM {database}.{name}\nWHERE {key} IS NOT NULL"
        )
    if not branches:
        return None
    return "\nUNION ALL\n".join(branches)


def build_uid_lookup_sql(database: str, tables: dict[str, set[str]]) -> str | None:
    return _build_lookup_sql(database, tables, "uid")


# File attributes worth carrying on fuid_lookup so "what was this file?" does not
# need a join back to files. Sources disagree on the name (`files.filename` vs
# `yara_corelight.file_name`), so each is a candidate list resolved per table.
_FILE_COLUMNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("filename", ("filename", "file_name")),
    ("mime_type", ("mime_type", "file_mime_type")),
    ("sha256", ("sha256",)),
    ("md5", ("md5",)),
)


def build_fuid_lookup_sql(database: str, tables: dict[str, set[str]]) -> str | None:
    """Every table carrying a fuid, plus the file attributes where present.

    The previous hand-made view covered only `files`; 6 tables carry a fuid here.
    But dropping filename/mime_type/sha256 would regress the agent prompt, which
    documents fuid_lookup as a file index, so they are projected with a per-source
    name fallback and NULL where a source has none.
    """
    branches: list[str] = []
    for name in sorted(tables):
        if name in _LOOKUP_EXCLUDE:
            continue
        cols = tables[name]
        if "fuid" not in cols or "dt" not in cols:
            continue
        select = ["  fuid AS fuid", f"  '{name}' AS log_type"]
        select += [f"  {_col_or_null(cols, s)} AS {a}" for s, a in _LOOKUP_COLUMNS]
        for alias, candidates in _FILE_COLUMNS:
            actual = next((c for c in candidates if c in cols), None)
            select.append(f"  {actual} AS {alias}" if actual
                          else f"  CAST(NULL AS VARCHAR) AS {alias}")
        select.append("  dt AS dt")
        branches.append(
            "SELECT\n" + ",\n".join(select)
            + f"\nFROM {database}.{name}\nWHERE fuid IS NOT NULL"
        )
    if not branches:
        return None
    return "\nUNION ALL\n".join(branches)


VIEW_BUILDERS = {
    "alerts": build_alerts_sql,
    "uid_lookup": build_uid_lookup_sql,
    "fuid_lookup": build_fuid_lookup_sql,
}


def build_view_ddl(database: str, tables: dict[str, set[str]]) -> dict[str, str]:
    """Return {view_name: full CREATE OR REPLACE VIEW statement}."""
    ddl: dict[str, str] = {}
    for view, builder in VIEW_BUILDERS.items():
        body = builder(database, tables)
        if body:
            ddl[view] = f"CREATE OR REPLACE VIEW {database}.{view} AS\n{body}"
    return ddl
