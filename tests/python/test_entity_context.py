"""Gates for entity_context (lambda/entity_context.py).

`uid_lookup` answers "what did this session do". This answers "what IS this host",
so a session can be pivoted to full entity context in ONE join instead of six.

The second hop exists because the known_* inventory tables do not carry the session
`uid`. They carry a `kuid` that appears in no session log and is per-observation
rather than per-host, so `host_ip` is the only real join key.

The property these gates protect above all else is NO FAN-OUT. Measured on live
data: `alerts` has up to 11,054 rows for one host and `known_services` up to 4,433,
so a naive alerts x services join produced 11,281,985 rows for a SINGLE host. Every
source must collapse to one row per host before anything is joined.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lambda"))

import entity_context as ec  # noqa: E402

DB = "testdb"
DATE = "2026-08-01"


def _catalog(**extra):
    cat = {
        "asset_classification": {"ip", "mac", "vendor_mac", "hostname", "os_name",
                                 "device_type", "org_name", "mgmt_tooling",
                                 "randomized_mac", "network_name", "room_name",
                                 "connections", "mb_in", "mb_out", "first_seen",
                                 "last_seen", "confidence", "dt"},
        "alerts": {"orig_h", "alert_type", "alert_name", "severity", "ts_datetime", "dt"},
        "known_users": {"host_ip", "user_", "protocol", "dt"},
        "known_services": {"host_ip", "service", "port_num", "dt"},
        "known_names": {"host_ip", "hostname", "dt"},
        "known_domains": {"host_ip", "domain", "dt"},
        "uid_lookup": {"uid", "orig_h", "log_type", "dt"},
    }
    cat.update(extra)
    return cat


class TestNoFanOut:
    """The whole reason this is aggregate-first rather than a join of raw rows."""

    def test_every_source_aggregates_before_joining(self):
        sql = ec.build_entity_context_sql(DB, DATE, _catalog())
        # Each CTE must GROUP BY its host key: that is what guarantees one row.
        assert sql.count("GROUP BY") >= 7, "a source is not aggregating"

    def test_alerts_are_counted_not_expanded(self):
        """One host has 11,054 alerts. They must become a number, not 11,054 rows."""
        sql = ec.build_entity_context_sql(DB, DATE, _catalog())
        assert "COUNT(*) alert_count_all" in sql
        assert "GROUP BY orig_h" in sql

    def test_services_are_counted_not_expanded(self):
        """One host has 4,433 services; crossed with its alerts that is 11.2M rows."""
        sql = ec.build_entity_context_sql(DB, DATE, _catalog())
        assert "COUNT(DISTINCT service) service_count" in sql

    def test_top_n_lists_are_bounded(self):
        """An unbounded ARRAY_AGG on a busy host makes one enormous cell."""
        sql = ec.build_entity_context_sql(DB, DATE, _catalog())
        assert "SLICE(ARRAY_AGG" in sql
        assert "ARRAY_AGG(DISTINCT alert_name), 1," in sql or "SLICE" in sql


class TestNoiseFiltering:
    """DNS resolvers log tens of thousands of ET INFO 'Observed DNS Query' rows. The
    live feed already excludes those, and these counts have to agree with the
    sidebar or the same host reads as catastrophic in one view and quiet in another."""

    def test_informational_prefixes_are_excluded_from_the_headline_count(self):
        sql = ec.build_entity_context_sql(DB, DATE, _catalog())
        assert "NOT LIKE 'ET INFO%'" in sql
        assert "NOT LIKE 'ETPRO INFO%'" in sql

    def test_raw_total_is_still_available(self):
        """Filtering must not destroy the information: a resolver's real volume is
        worth seeing if someone asks for it explicitly."""
        sql = ec.build_entity_context_sql(DB, DATE, _catalog())
        assert "alert_count_all" in sql
        assert "alert_count" in sql

    def test_high_severity_count_also_excludes_noise(self):
        sql = ec.build_entity_context_sql(DB, DATE, _catalog())
        high = sql[sql.index("high_alert_count") - 400:sql.index("high_alert_count")]
        assert "ET INFO" in high, "high_alert_count is counting informational rows"


class TestPartialCatalog:
    def test_returns_none_when_nothing_joinable_exists(self):
        assert ec.build_entity_context_sql(DB, DATE, {}) is None

    def test_a_missing_source_degrades_to_nulls(self):
        """A host should still get identity even if it has no alerts, and vice
        versa, so a partial catalog must not drop whole columns."""
        cat = _catalog()
        del cat["known_users"]
        sql = ec.build_entity_context_sql(DB, DATE, cat)
        assert f"{DB}.known_users" not in sql
        assert "observed_users" in sql, "column vanished instead of becoming NULL"

    def test_alerts_only_catalog_still_builds(self):
        sql = ec.build_entity_context_sql(DB, DATE, {"alerts": {"orig_h", "alert_name",
                                                               "alert_type", "severity",
                                                               "ts_datetime", "dt"}})
        assert sql is not None
        assert "alert_count" in sql


class TestJoinSemantics:
    def test_full_outer_join_so_no_host_is_lost(self):
        """A host can be inventoried without alerting, or alert without ever being
        inventoried. Starting from one spine would silently drop the other kind."""
        sql = ec.build_entity_context_sql(DB, DATE, _catalog())
        assert "FULL OUTER JOIN" in sql
        assert "LEFT JOIN" not in sql

    def test_ip_is_coalesced_across_every_source(self):
        sql = ec.build_entity_context_sql(DB, DATE, _catalog())
        assert "COALESCE(" in sql and " ip" in sql

    def test_partition_is_pinned(self):
        """Unpinned, this would scan every day in the catalog on every rebuild."""
        sql = ec.build_entity_context_sql(DB, DATE, _catalog())
        assert f"dt = '{DATE}'" in sql


class TestPivotColumns:
    """The columns that make the uid -> entity pivot worth a single query."""

    @pytest.mark.parametrize("col", [
        "hostname", "os_name", "org_name", "mac", "vendor_mac",   # identity
        "observed_users", "user_count",                            # accounts
        "service_count", "listening_ports",                        # exposure
        "alert_count", "high_alert_count", "top_alerts",           # risk
        "session_count", "log_type_count", "log_types",            # reach
    ])
    def test_column_is_present(self, col):
        assert col in ec.build_entity_context_sql(DB, DATE, _catalog())


class TestDDL:
    def test_table_is_per_day(self):
        assert ec.table_name(DATE) == "entity_context_2026_08_01"

    def test_ctas_targets_that_table(self):
        ddl = ec.build_ctas(DB, DATE, _catalog())
        assert ddl.startswith(f"CREATE TABLE {DB}.entity_context_2026_08_01 AS")

    def test_ctas_omits_external_location(self):
        """The workgroup enforces a centralized output path and rejects a CTAS that
        names its own."""
        assert "external_location" not in ec.build_ctas(DB, DATE, _catalog())

    def test_ctas_is_none_when_unsatisfiable(self):
        assert ec.build_ctas(DB, DATE, {}) is None
