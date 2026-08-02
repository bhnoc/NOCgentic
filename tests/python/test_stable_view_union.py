"""Gate: the stable view over a per-day materialized table must cover EVERY day.

`asset_classification` is rebuilt as one table per day (asset_classification_2026_08_02)
with a stable view in front so agents query one name. That view was defined as
`SELECT * FROM <newest table>`, which made a perfectly reasonable filter return
nothing at all:

    SELECT ... FROM asset_classification WHERE dt = '2026-08-01'   -->  0 rows

while 108,686 rows sat in asset_classification_2026_08_01. No error, no warning —
an empty result, which an agent faithfully reports to an analyst as "no data for
that day". Three QA validators lost queries to it before anyone noticed. Measured
after the fix: 108,686 for 08-01, 42,058 for 08-02, 150,744 across all dt.

The arms name their columns explicitly instead of `SELECT *`. Two reasons:
`UNION ALL BY NAME` would say this directly but Athena rejects it ("mismatched
input 'BY'"), and a positional `SELECT *` union across partitions built from a
DISCOVERED catalog will transpose values the day a schema gains a column — a wrong
value under a right column name, which beats a hard failure for sheer damage.
"""

import importlib.util
import os
import sys

import pytest

_LAMBDA = os.path.join(os.path.dirname(__file__), "..", "..", "lambda")
sys.path.insert(0, _LAMBDA)

NEWEST = "asset_classification_2026_08_02"
OLDER = "asset_classification_2026_08_01"

# The newest partition's column order defines the view's column order.
NEW_COLS = ["ip", "os_name", "device_type", "os_source", "confidence", "dt"]
# The older partition predates os_source, which is exactly the drift that makes a
# positional union dangerous.
OLD_COLS = ["ip", "os_name", "device_type", "confidence", "dt"]


@pytest.fixture()
def refresh(monkeypatch):
    for k, v in {
        "REGION": "us-east-2", "S3_LOG_BUCKET": "b", "S3_LOG_PREFIX": "p",
        "S3_PARQUET_BUCKET": "b", "GLUE_DATABASE": "d", "ATHENA_WORKGROUP": "w",
    }.items():
        os.environ.setdefault(k, v)
    path = os.path.join(_LAMBDA, "athena_refresh_lambda_v6.py")
    spec = importlib.util.spec_from_file_location("refresh_view_mod", path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:
        pytest.skip(f"lambda deps unavailable: {exc}")

    monkeypatch.setattr(mod, "_catalog_columns", lambda: {
        NEWEST: set(NEW_COLS),
        OLDER: set(OLD_COLS),
        "conn": {"id_orig_h", "dt"},
        "entity_context_2026_08_02": {"ip", "dt"},
    })
    monkeypatch.setattr(mod, "_table_column_order",
                        lambda t: NEW_COLS if t == NEWEST else OLD_COLS)
    return mod


class TestEveryPartitionIsIncluded:
    def test_older_partition_is_in_the_view(self, refresh):
        """The bug: the view pinned only the newest table, so a dt filter for any
        other retained day returned zero rows with no error."""
        ddl = refresh._stable_view_ddl("asset_classification", NEWEST)
        assert OLDER in ddl, "older partition dropped; a dt filter will return 0 rows"
        assert NEWEST in ddl

    def test_arms_are_unioned(self, refresh):
        ddl = refresh._stable_view_ddl("asset_classification", NEWEST)
        assert ddl.count("UNION ALL") == 1, "two partitions should give exactly one UNION"

    def test_unrelated_tables_are_not_swept_in(self, refresh):
        """Prefix matching must not pull in entity_context or raw logs."""
        ddl = refresh._stable_view_ddl("asset_classification", NEWEST)
        assert "entity_context" not in ddl
        assert ".conn" not in ddl

    def test_newest_table_is_included_even_if_not_yet_in_the_catalog(self, refresh):
        """The CTAS that just created today's table can precede catalog visibility;
        omitting it would publish a view without today's data."""
        ddl = refresh._stable_view_ddl("asset_classification", "asset_classification_2026_08_03")
        assert "asset_classification_2026_08_03" in ddl


class TestColumnAlignment:
    def test_no_star_select(self, refresh):
        """A positional union across a discovered catalog transposes values as soon
        as one partition has fewer columns than another."""
        ddl = refresh._stable_view_ddl("asset_classification", NEWEST)
        assert "SELECT *" not in ddl

    def test_union_all_by_name_is_not_used(self, refresh):
        """Athena rejects it outright: mismatched input 'BY'."""
        ddl = refresh._stable_view_ddl("asset_classification", NEWEST)
        assert "BY NAME" not in ddl

    def test_missing_column_becomes_a_typed_null(self, refresh):
        """The older partition has no os_source. It must still contribute a column
        of that name so the arms line up."""
        ddl = refresh._stable_view_ddl("asset_classification", NEWEST)
        assert 'CAST(NULL AS VARCHAR) AS "os_source"' in ddl

    def test_every_arm_lists_the_same_columns_in_the_same_order(self, refresh):
        ddl = refresh._stable_view_ddl("asset_classification", NEWEST)
        arms = ddl.split(" UNION ALL ")
        assert len(arms) == 2
        names = []
        for arm in arms:
            body = arm[arm.index("SELECT ") + 7:arm.index(" FROM ")]
            names.append([c.split(' AS "')[-1].strip('"') if " AS " in c
                          else c.strip().strip('"')
                          for c in body.split(", ")])
        assert names[0] == names[1] == NEW_COLS


class TestDegradation:
    def test_none_when_no_partitions_exist(self, refresh, monkeypatch):
        """A first run with nothing built must not emit a view over zero tables."""
        monkeypatch.setattr(refresh, "_catalog_columns", lambda: {})
        monkeypatch.setattr(refresh, "_table_column_order", lambda t: [])
        assert refresh._stable_view_ddl("asset_classification", "") is None

    def test_none_when_column_order_is_unavailable(self, refresh, monkeypatch):
        """Without an order there is no safe arm to build; skip rather than guess."""
        monkeypatch.setattr(refresh, "_table_column_order", lambda t: [])
        monkeypatch.setattr(refresh, "_catalog_columns", lambda: {NEWEST: set()})
        assert refresh._stable_view_ddl("asset_classification", NEWEST) is None

    def test_works_for_entity_context_too(self, refresh, monkeypatch):
        """The same helper backs entity_context and device_links, so the bug class
        is fixed once rather than per table."""
        monkeypatch.setattr(refresh, "_catalog_columns", lambda: {
            "entity_context_2026_08_01": {"ip", "dt"},
            "entity_context_2026_08_02": {"ip", "dt"},
        })
        monkeypatch.setattr(refresh, "_table_column_order", lambda t: ["ip", "dt"])
        ddl = refresh._stable_view_ddl("entity_context", "entity_context_2026_08_02")
        assert "entity_context_2026_08_01" in ddl and "UNION ALL" in ddl
