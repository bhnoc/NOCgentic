"""Gates for the raw -> Parquet loader's positional reads (athena_refresh_lambda_v6).

The loader has no schema registry. It reads a Zeek `#fields` header, turns it into
column POSITIONS, and then `element_at(split(line, chr(9)), N)` every row. Every bug
in this file is the same shape: N pointed at the wrong field, so a real value shipped
under the wrong column name. That is worse than a NULL, because nothing downstream can
tell it apart from data.

Three were live on 2026-08-01, all measured against dt=2026-08-01:

  1. RENAMED COLUMNS. The loader used to append '_' to reserved words (`user` ->
     `user_`); commit 9b2549a switched to backtick-quoting and dropped the rename. But
     CREATE TABLE IF NOT EXISTS never rewrites an existing table, so tables built under
     the old scheme still have `user_` while the header says `user`. The lookup missed
     and every row got CAST(NULL). known_users.user_ went from populated to exactly 0
     the hour that commit shipped (18:xx populated, 19:00 empty, commit at 19:09 UTC),
     and smtp's date_/from_/to_ with it.

  2. MULTIPLE HEADER SHAPES. `conn` ships two headers -- 68 data fields and 70 --
     because cli_rtt/svr_rtt are optional and sit MID-SCHEMA, so everything after them
     shifts by two. conn_long (72/74), http, quic and ssl are the same. The loader read
     ONE header via LIMIT 1 and applied it to every row, so the whole tail of the other
     variant was off by two: remote_country is at 62 in one and 64 in the other, which
     is why the 'country' column held remote_city's hash. entity_context's comment
     blamed "40-char hex hashes" in the data -- the data was fine, the read was shifted.

  3. $path PREFIX COLLISION. Files are named `<log_type>_<YYYYMMDD>_<time>.log.gz` and
     the filter was `LIKE '%/{log_type}_%'`, so '%/conn_%' also matched
     conn_long_20260801_*. SIX tables were loading a foreign log type's rows with a
     different field order on top of their own: conn<-conn_long,
     dce_rpc<-dce_rpc_activity, dhcp<-dhcp_fp_lite, files<-files_metadata,
     ldap<-ldap_search, profinet<-profinet_dce_rpc.
"""

import importlib.util
import os
import re
import sys

import pytest

_LAMBDA = os.path.join(os.path.dirname(__file__), "..", "..", "lambda")
sys.path.insert(0, _LAMBDA)


@pytest.fixture(scope="module")
def refresh():
    for k, v in {
        "REGION": "us-east-2", "S3_LOG_BUCKET": "b", "S3_LOG_PREFIX": "p",
        "S3_PARQUET_BUCKET": "b", "GLUE_DATABASE": "d", "ATHENA_WORKGROUP": "w",
    }.items():
        os.environ.setdefault(k, v)
    path = os.path.join(_LAMBDA, "athena_refresh_lambda_v6.py")
    spec = importlib.util.spec_from_file_location("refresh_align_mod", path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"lambda deps unavailable: {exc}")
    return mod


# The two REAL conn headers, read off dt=2026-08-01. Trimmed to the shape that matters:
# a common head, the optional mid-schema pair, and the geo tail that the shift corrupts.
_CONN_NARROW = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
    "service", "duration", "orig_bytes", "resp_bytes", "conn_state",
    "vlan", "inner_vlan",
    "remote_asn", "remote_organization", "remote_city", "remote_country",
]
# cli_rtt/svr_rtt appear BEFORE the geo block, so everything after shifts by 2.
_CONN_WIDE = _CONN_NARROW[:12] + ["svr_rtt", "cli_rtt"] + _CONN_NARROW[12:]


def _schemas():
    return {len(_CONN_NARROW): _CONN_NARROW, len(_CONN_WIDE): _CONN_WIDE}


def _capture_insert(refresh, log_type, table_cols, schemas, last_ts=None):
    """Run incremental_load with Athena stubbed, return the INSERT it would issue."""
    sent = []
    real_schemas = refresh.get_schemas_from_raw
    real_query = refresh.run_athena_query
    real_athena = refresh.athena
    try:
        refresh.get_schemas_from_raw = lambda lt, d: schemas
        refresh.run_athena_query = lambda q, **k: (sent.append(q), ("qid", "SUCCEEDED", None))[1]
        refresh.athena = type("A", (), {
            "get_query_results": staticmethod(lambda **k: {"ResultSet": {"Rows": []}})
        })()
        ok, _ = refresh.incremental_load(log_type, table_cols, "2026-08-01", last_ts)
    finally:
        refresh.get_schemas_from_raw = real_schemas
        refresh.run_athena_query = real_query
        refresh.athena = real_athena
    assert ok, "incremental_load reported failure"
    return sent[0]


def _select_exprs(insert_sql):
    body = insert_sql.split("SELECT", 1)[1].split("\nFROM", 1)[0]
    return [e.strip() for e in body.split(",\n")]


def _positions_read(expr):
    """Every field position this expression can read."""
    return sorted(int(n) for n in re.findall(r"chr\(9\)\), (\d+)\)", expr))


class TestRenamedColumnsStillBind:
    """Bug 1. The table outlives the naming scheme that created it."""

    def test_a_trailing_underscore_column_binds_to_the_bare_field(self, refresh):
        field_map = {"ts": 1, "host_ip": 2, "user": 3, "protocol": 4}
        assert refresh.resolve_field_index(field_map, "user_") == 3

    def test_an_exact_match_always_wins_over_the_fallback(self, refresh):
        """A log type that genuinely has both `foo` and `foo_` must not be
        redirected. The fallback is a fallback, not a rewrite."""
        field_map = {"foo": 1, "foo_": 2}
        assert refresh.resolve_field_index(field_map, "foo_") == 2
        assert refresh.resolve_field_index(field_map, "foo") == 1

    def test_a_genuinely_absent_column_is_still_absent(self, refresh):
        assert refresh.resolve_field_index({"a": 1}, "nope") is None
        assert refresh.resolve_field_index({"a": 1}, "nope_") is None

    @pytest.mark.parametrize("col,field", [
        ("user_", "user"), ("date_", "date"), ("from_", "from"), ("to_", "to"),
        ("group_", "group"), ("table_", "table"), ("order_", "order"),
    ])
    def test_every_word_the_old_reserved_list_renamed_is_recovered(
            self, refresh, col, field):
        """The old list had 19 words. Any table created while it was in force can
        carry the renamed form, so all of them must resolve."""
        assert refresh.resolve_field_index({field: 7}, col) == 7

    def test_known_users_emits_a_real_read_not_a_null_cast(self, refresh):
        """The end-to-end form: the live table has `user_`, the header says `user`,
        and the generated SQL must read position 3 rather than CAST(NULL)."""
        schemas = {4: ["ts", "host_ip", "user", "protocol"]}
        cols = [("ts_datetime", "string"), ("host_ip", "string"),
                ("user_", "string"), ("protocol", "string"), ("dt", "string")]
        exprs = _select_exprs(_capture_insert(refresh, "known_users", cols, schemas))
        user_expr = exprs[2]
        assert "CAST(NULL" not in user_expr, "the regression is back"
        assert _positions_read(user_expr) == [3]

    def test_smtp_recovers_all_three_renamed_columns(self, refresh):
        schemas = {5: ["ts", "uid", "date", "from", "to"]}
        cols = [("ts_datetime", "string"), ("uid", "string"), ("date_", "string"),
                ("from_", "string"), ("to_", "string"), ("dt", "string")]
        exprs = _select_exprs(_capture_insert(refresh, "smtp", cols, schemas))
        for i, pos in ((2, 3), (3, 4), (4, 5)):
            assert "CAST(NULL" not in exprs[i], exprs[i]
            assert _positions_read(exprs[i]) == [pos]


class TestEveryHeaderVariantIsRead:
    """Bug 2. One header cannot describe two field orders."""

    def test_all_distinct_headers_are_returned(self, refresh):
        rows = [{"Data": [{"VarCharValue": "hdr"}]}]  # header row, skipped
        for fields in (_CONN_NARROW, _CONN_WIDE):
            rows.append({"Data": [{"VarCharValue": "#fields\t" + "\t".join(fields)}]})
        real_q, real_a = refresh.run_athena_query, refresh.athena
        try:
            refresh.run_athena_query = lambda q, **k: ("qid", "SUCCEEDED", None)
            refresh.athena = type("A", (), {
                "get_query_results": staticmethod(
                    lambda **k: {"ResultSet": {"Rows": rows}})
            })()
            got = refresh.get_schemas_from_raw("conn", "2026-08-01")
        finally:
            refresh.run_athena_query, refresh.athena = real_q, real_a
        assert set(got) == {len(_CONN_NARROW), len(_CONN_WIDE)}

    def test_ddl_is_built_from_the_widest_header(self, refresh):
        """A narrow header would permanently lose the optional columns for every row;
        the wide one simply leaves them NULL where absent."""
        real = refresh.get_schemas_from_raw
        try:
            refresh.get_schemas_from_raw = lambda lt, d: _schemas()
            fields = refresh.get_schema_from_raw("conn", "2026-08-01")
        finally:
            refresh.get_schemas_from_raw = real
        assert fields == _CONN_WIDE
        assert "cli_rtt" in fields

    def test_a_shifted_column_dispatches_on_field_count(self, refresh):
        """remote_country is at 16 in the narrow header and 18 in the wide one. Both
        must be read, each only for its own row shape."""
        cols = [("ts_datetime", "string"), ("remote_country", "string"),
                ("dt", "string")]
        expr = _select_exprs(
            _capture_insert(refresh, "conn", cols, _schemas()))[1]
        narrow = _CONN_NARROW.index("remote_country") + 1
        wide = _CONN_WIDE.index("remote_country") + 1
        assert narrow != wide, "fixture no longer exercises a shift"
        assert _positions_read(expr) == sorted([narrow, wide])
        assert f"IN ({len(_CONN_NARROW)})" in expr
        assert f"IN ({len(_CONN_WIDE)})" in expr

    def test_a_field_only_in_one_variant_stays_guarded(self, refresh):
        """THE TRAP IN THE FIX ITSELF. cli_rtt exists only in the wide header, so it
        maps to exactly ONE position -- which invites collapsing it to an unguarded
        read. But a narrow row has a DIFFERENT field at that position ('inner_vlan'),
        so the unguarded form files inner_vlan under cli_rtt. Presence in one variant
        is not the same as agreement across all of them."""
        cols = [("ts_datetime", "string"), ("cli_rtt", "string"), ("dt", "string")]
        expr = _select_exprs(_capture_insert(refresh, "conn", cols, _schemas()))[1]
        assert f"IN ({len(_CONN_WIDE)})" in expr, (
            "cli_rtt must be restricted to the variant that has it")
        assert f"IN ({len(_CONN_NARROW)})" not in expr
        # And prove the position it would have leaked is a different field.
        pos = _CONN_WIDE.index("cli_rtt") + 1
        assert _CONN_NARROW[pos - 1] != "cli_rtt"

    def test_a_field_at_the_same_position_everywhere_is_not_wrapped(self, refresh):
        """Ahead of the optional block nothing shifts, which is the common case. A
        needless CASE on every one of 70 columns is cost for no correctness."""
        cols = [("ts_datetime", "string"), ("id_orig_h", "string"), ("dt", "string")]
        expr = _select_exprs(_capture_insert(refresh, "conn", cols, _schemas()))[1]
        assert "IN (" not in expr
        assert _positions_read(expr) == [_CONN_WIDE.index("id.orig_h") + 1]

    def test_an_unknown_row_shape_yields_null_never_a_guess(self, refresh):
        """A header the loader has not seen must not be read at a guessed offset: a
        wrong position ships a real value under the wrong name, which no consumer can
        detect. NULL is the honest answer."""
        cols = [("ts_datetime", "string"), ("remote_country", "string"),
                ("dt", "string")]
        expr = _select_exprs(_capture_insert(refresh, "conn", cols, _schemas()))[1]
        assert re.search(r"ELSE CAST\(NULL AS \w+\) END\s*$", expr), expr

    def test_the_geo_tail_never_reads_a_neighbours_position(self, refresh):
        """The measured symptom: remote_country held remote_city's value. For each
        geo column, every position it can read must be that column in the variant it
        is guarded to."""
        geo = ["remote_asn", "remote_organization", "remote_city", "remote_country"]
        cols = ([("ts_datetime", "string")] + [(g, "string") for g in geo]
                + [("dt", "string")])
        exprs = _select_exprs(_capture_insert(refresh, "conn", cols, _schemas()))
        for i, name in enumerate(geo, start=1):
            allowed = {_CONN_NARROW.index(name) + 1, _CONN_WIDE.index(name) + 1}
            assert set(_positions_read(exprs[i])) == allowed, name


class TestSchemaEvolutionIsReconciled:
    """Bug 4. CREATE TABLE IF NOT EXISTS runs once; Corelight keeps adding fields.

    Measured on dt=2026-08-01, EVERY multi-variant table was missing its newer field
    outright -- the loader read the value correctly and then had nowhere to put it:
    cli_rtt/svr_rtt (conn, conn_long), hs_delay (ssl, quic), tx_delay/trans_time (http).
    """

    def _alter(self, refresh, fields, existing_cols):
        sent = []
        real_s, real_q = refresh.get_schema_from_raw, refresh.run_athena_query
        try:
            refresh.get_schema_from_raw = lambda lt, d: fields
            refresh.run_athena_query = lambda q, **k: (
                sent.append(q), ("qid", "SUCCEEDED", None))[1]
            added = refresh.reconcile_table_columns("conn", "2026-08-01", existing_cols)
        finally:
            refresh.get_schema_from_raw, refresh.run_athena_query = real_s, real_q
        return added, (sent[0] if sent else None)

    def test_a_new_mid_schema_field_is_added(self, refresh):
        existing = [(refresh.sanitize_column_name(f), "string")
                    for f in _CONN_NARROW] + [("ts_datetime", "string")]
        added, sql = self._alter(refresh, _CONN_WIDE, existing)
        assert set(added) == {"cli_rtt", "svr_rtt"}
        assert "ADD COLUMNS" in sql
        assert "`cli_rtt` string" in sql and "`svr_rtt` string" in sql

    def test_it_is_a_no_op_once_the_table_is_current(self, refresh):
        """Safe to run on every pass, which is what makes it a reconciliation rather
        than a migration someone has to remember."""
        existing = [(refresh.sanitize_column_name(f), "string")
                    for f in _CONN_WIDE] + [("ts_datetime", "string")]
        added, sql = self._alter(refresh, _CONN_WIDE, existing)
        assert added == []
        assert sql is None, "an ALTER was issued with nothing to add"

    def test_a_renamed_column_is_not_duplicated(self, refresh):
        """THE TRAP. A table created under the old scheme has `user_`; the header says
        `user`. resolve_field_index already binds those, so `user` is NOT missing --
        adding it would create a second column and split the data between the two."""
        existing = [("ts_datetime", "string"), ("ts", "DOUBLE"),
                    ("host_ip", "string"), ("user_", "string"),
                    ("protocol", "string")]
        added, sql = self._alter(
            refresh, ["ts", "host_ip", "user", "protocol"], existing)
        assert "user" not in added, f"would duplicate the renamed column: {added}"
        assert added == [] and sql is None

    def test_columns_are_never_dropped_or_retyped(self, refresh):
        """Additive only. An extra column is harmless; removing one that a derived view
        or an agent's generated SQL still names breaks reads."""
        existing = [("ts_datetime", "string"), ("ts", "DOUBLE"),
                    ("uid", "string"), ("long_gone_column", "string")]
        added, sql = self._alter(refresh, ["ts", "uid", "brand_new"], existing)
        assert added == ["brand_new"]
        for forbidden in ("DROP", "REPLACE COLUMNS", "CHANGE"):
            assert forbidden not in (sql or "").upper()

    def test_a_failed_alter_does_not_fail_the_refresh(self, refresh):
        """Trading a missing field for a missing HOUR of data is a bad trade."""
        real_s, real_q = refresh.get_schema_from_raw, refresh.run_athena_query
        try:
            refresh.get_schema_from_raw = lambda lt, d: _CONN_WIDE
            refresh.run_athena_query = lambda q, **k: ("qid", "FAILED", "boom")
            added = refresh.reconcile_table_columns(
                "conn", "2026-08-01",
                [(refresh.sanitize_column_name(f), "string") for f in _CONN_NARROW])
        finally:
            refresh.get_schema_from_raw, refresh.run_athena_query = real_s, real_q
        assert added == []

    @pytest.mark.parametrize("log_type,field", [
        ("conn", "cli_rtt"), ("conn", "svr_rtt"),
        ("conn_long", "cli_rtt"), ("conn_long", "svr_rtt"),
        ("ssl", "hs_delay"), ("quic", "hs_delay"),
        ("http", "tx_delay"), ("http", "trans_time"),
    ])
    def test_every_measured_missing_field_would_be_added(
            self, refresh, log_type, field):
        """The concrete inventory, so a regression names the field it lost."""
        existing = [("ts_datetime", "string"), ("ts", "DOUBLE"), ("uid", "string")]
        added, _ = self._alter(refresh, ["ts", "uid", field], existing)
        assert field in added

    def test_reconciliation_runs_before_the_load(self, refresh):
        """A column added after the SELECT is built stays empty for that run, so the
        table list must be re-read. Guards the ordering, not just the call."""
        src = open(os.path.join(_LAMBDA, "athena_refresh_lambda_v6.py")).read()
        body = src.split("def process_single", 1)[1].split("\ndef ", 1)[0]
        # Comments mention both names, so anchor on the CALLS: `incremental_load(` with
        # its paren, and only lines that are not comments.
        code = "\n".join(l for l in body.splitlines()
                         if not l.strip().startswith("#"))
        assert "reconcile_table_columns(" in code, "never called from the worker"
        recon = code.index("reconcile_table_columns(")
        load = code.index("success, new_ts = incremental_load(")
        assert recon < load, "reconciliation runs after the load"
        assert "get_existing_tables()" in code[recon:load], (
            "the table list is not re-read, so new columns stay NULL for that run")


class TestPathPredicateIsAnchored:
    """Bug 3. `conn_long` is not `conn`."""

    # Every real prefix collision in the catalog, measured on dt=2026-08-01.
    COLLISIONS = [
        ("conn", "conn_long"),
        ("dce_rpc", "dce_rpc_activity"),
        ("dhcp", "dhcp_fp_lite"),
        ("files", "files_metadata"),
        ("ldap", "ldap_search"),
        ("profinet", "profinet_dce_rpc"),
    ]

    def _matches(self, refresh, log_type, filename):
        pred = refresh.path_predicate(log_type)
        pattern = re.search(r"'(.+)'\)$", pred).group(1)
        return re.search(pattern, filename) is not None

    @pytest.mark.parametrize("short,long_", COLLISIONS)
    def test_a_shorter_name_does_not_swallow_a_longer_one(
            self, refresh, short, long_):
        own = f"/{short}_20260801_01:35:00-01:40:00+0000-5.log.gz"
        foreign = f"/{long_}_20260801_01:15:00-01:20:00+0000-5.log.gz"
        assert self._matches(refresh, short, own)
        assert not self._matches(refresh, short, foreign), (
            f"{short} is still ingesting {long_}")
        assert self._matches(refresh, long_, foreign)
        assert not self._matches(refresh, long_, own)

    def test_the_date_is_what_anchors_the_name(self, refresh):
        """'_' is a single-character wildcard in SQL LIKE, so the boundary has to be
        the 8-digit date rather than a literal underscore."""
        assert not self._matches(
            refresh, "conn", "/connX20260801_01:00:00-x.log.gz")
        assert not self._matches(
            refresh, "conn", "/conn_2026080_01:00:00-x.log.gz")  # 7 digits
        assert self._matches(refresh, "conn", "/conn_20260801_01:00:00-x.log.gz")

    def test_a_hyphenated_log_type_is_regex_escaped(self, refresh):
        """krb5-auth is a real log type. An unescaped '-' is harmless here but the
        name is interpolated into a regex, so it must not be able to carry syntax."""
        assert self._matches(
            refresh, "krb5-auth", "/krb5-auth_20260801_01:00:00-x.log.gz")
        assert not self._matches(
            refresh, "krb5-auth", "/krb5Xauth_20260801_01:00:00-x.log.gz")

    def test_both_query_sites_use_the_predicate(self, refresh):
        """The schema read and the INSERT must agree. If only one is anchored, the
        loader derives a field map from one log type and applies it to another --
        which is bug 2 and bug 3 compounding."""
        src = open(os.path.join(_LAMBDA, "athena_refresh_lambda_v6.py")).read()
        assert "LIKE '%/{log_type}_%'" not in src, "an unanchored $path filter remains"
        assert src.count("path_predicate(log_type)") >= 2

    def test_the_insert_filters_on_the_anchored_predicate(self, refresh):
        cols = [("ts_datetime", "string"), ("remote_country", "string"),
                ("dt", "string")]
        sql = _capture_insert(refresh, "conn", cols, _schemas())
        assert 'REGEXP_LIKE("$path"' in sql
        assert "'/conn_[0-9]{8}_'" in sql
