"""Gates for the discovery-driven Athena view builder (lambda/derived_views.py).

Why this exists: the previous derived views were hand-maintained UNIONs in another
account. They drifted badly (uid_lookup covered 9 tables when 37 carried a uid) and
did not follow the account move at all, which is what left the live alert feed
returning an empty list while 440k real alerts sat in the catalog.

These lock the two properties that keep that from recurring:
  1. membership comes from the catalog, not a hardcoded list
  2. a missing or differently-shaped source degrades that one branch, never the view
"""

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lambda"))

import derived_views as dv  # noqa: E402

DB = "testdb"

# The columns Corelight's alert-ish logs actually carry, as observed in prod.
_COMMON = {
    "ts_datetime", "ts", "uid", "id_orig_h", "id_orig_p", "id_resp_h",
    "id_resp_p", "id_orig_network_name", "dt",
}


def _catalog(**extra: set) -> dict[str, set]:
    """A minimal but realistic catalog: the four live alert sources plus extras."""
    cat = {
        "suricata_corelight": _COMMON | {"alert_signature", "alert_category", "alert_severity"},
        "notice": _COMMON | {"note", "msg", "severity_name", "fuid"},
        "corelight_ml_results": _COMMON | {"predicted_tag_name", "predicted_probability",
                                           "domain", "nearest_ref_domain"},
        "yara_corelight": _COMMON | {"match_rule", "file_name", "sha256", "fuid"},
        "conn": _COMMON,
        "dns": _COMMON,
        "weird": _COMMON | {"name", "addl"},
        "corelight_ml_metrics": {"ts_datetime", "dt"},  # no uid: a rollup, not sessions
    }
    cat.update(extra)
    return cat


# Real anomaly record schema, from a sibling Corelight sensor (2026-08-01).
# Shaped unlike every other alert source: no id_orig_h, CIDR-shaped host fields,
# a 0-1 score, and a ~400-element array of mostly out-of-scope CIDRs.
_ANOMALY_COLS = {
    "ts_datetime", "ts", "uid", "use_case", "use_case_description", "entity",
    "original_entity", "entity_training_items", "item", "item_score",
    "item_assoc_entities", "item_assoc_entities_similarity", "ignorable",
    "history_days", "history", "dt",
}


class TestAlertSources:
    def test_all_four_live_sources_present(self):
        sql = dv.build_alerts_sql(DB, _catalog())
        for t in ("suricata_corelight", "notice", "corelight_ml_results", "yara_corelight"):
            assert f"{DB}.{t}" in sql, f"{t} missing from alerts"

    def test_weird_is_not_an_alert_source(self):
        """weird is protocol telemetry at ~20x suricata's volume; it buried every
        real IDS hit in a recency-ordered feed. It is NOT the anomaly detector."""
        sql = dv.build_alerts_sql(DB, _catalog())
        assert f"{DB}.weird" not in sql

    def test_weird_still_reachable_via_uid_lookup(self):
        """Excluded from alerts, but a session's weird lines still matter."""
        sql = dv.build_uid_lookup_sql(DB, _catalog())
        assert f"{DB}.weird" in sql

    def test_anomaly_absent_today_is_a_noop(self):
        """The detector has to baseline first, so the table does not exist yet.
        Pre-wiring it must not break the view."""
        sql = dv.build_alerts_sql(DB, _catalog())
        assert f"{DB}.anomaly" not in sql
        assert sql.count("UNION ALL") == 3  # four branches

    def test_anomaly_self_activates_when_the_table_appears(self):
        """The whole point of pre-wiring: no code change mid-show. Uses the REAL
        anomaly schema (use_case/original_entity/item_score), not weird's shape."""
        sql = dv.build_alerts_sql(DB, _catalog(anomaly=_ANOMALY_COLS))
        assert f"{DB}.anomaly" in sql
        assert "'anomaly' AS alert_type" in sql

    def test_source_with_unexpected_schema_is_skipped_not_fatal(self):
        """If the sensor emits different column names, that branch drops and the
        other four still build. Silent partial beats a broken view."""
        cat = _catalog(anomaly={"ts_datetime", "ts", "dt", "score", "detector"})
        sql = dv.build_alerts_sql(DB, cat)
        assert f"{DB}.anomaly" not in sql
        assert sql and sql.count("UNION ALL") == 3

    def test_missing_optional_column_becomes_null_not_an_error(self):
        """Corelight schemas vary by log type and sensor version."""
        cat = _catalog()
        cat["notice"] = cat["notice"] - {"id_resp_p"}
        sql = dv.build_alerts_sql(DB, cat)
        assert "CAST(NULL AS VARCHAR) AS resp_p" in sql


class TestSeverityVocabulary:
    """The app's _normalize_severity maps anything outside its valid set to
    'unknown'. Emitting 'info' silently mislabeled every row from that source."""

    def test_never_emits_the_invalid_info_literal(self):
        sql = dv.build_alerts_sql(DB, _catalog())
        assert "'info'" not in sql, "use 'informational'; the app maps 'info' -> unknown"

    def test_suricata_severity_1_is_high(self):
        """Recovered from the original view, not guessed: 1 is most severe."""
        sql = dv.build_alerts_sql(DB, _catalog())
        assert "WHEN 1 THEN 'high'" in sql

    def test_yara_hit_is_high(self):
        """A YARA match is a positive malware signature, not informational."""
        src = next(s for s in dv.ALERT_SOURCES if s["table"] == "yara_corelight")
        assert src["severity"] == "'high'"

    def test_no_source_passes_its_raw_severity_through(self):
        """notice was the only arm shipping its source's string verbatim
        (COALESCE(severity_name,'unknown')), and Zeek does not use this app's
        vocabulary. Every arm must map into the closed set."""
        for src in dv.ALERT_SOURCES:
            sev = src["severity"]
            if sev.startswith("'"):
                continue  # a literal is already in-vocabulary
            assert "CASE" in sev.upper(), (
                f"{src['table']} passes its raw severity through: {sev}")

    @pytest.mark.parametrize("raw,expected", [
        # The three values MEASURED in alerts on dt=2026-08-01 that were outside the
        # vocabulary: 'error' 2,965 rows, 'informational (default)' 239,
        # 'notification' 22. severity IN ('critical','high') skipped every one, so
        # 2,965 real high-severity notices were invisible to every correct filter.
        ("error", "high"),
        ("notification", "low"),
        ("informational (default)", "informational"),
        # Already-canonical values pass through.
        ("critical", "critical"), ("high", "high"), ("medium", "medium"),
        ("low", "low"), ("informational", "informational"),
        # Anything unrecognised becomes 'unknown', NOT 'low', so a new Zeek severity
        # stays visible instead of being buried at the bottom of a sorted feed.
        ("Notice::Tally", "unknown"), ("", "unknown"), ("weird_new_value", "unknown"),
    ])
    def test_notice_severity_is_folded_into_the_vocabulary(self, raw, expected):
        """Mirrors the emitted CASE. The mapping matches alert-triage._norm_sev /
        athena-hunter._WORD_SEV, which are the source of truth."""
        mapping = {
            "error": "high", "notification": "low",
            "informational (default)": "informational",
            "critical": "critical", "high": "high", "medium": "medium",
            "low": "low", "informational": "informational",
        }
        assert mapping.get(raw.strip().lower(), "unknown") == expected

    def test_the_notice_arm_maps_every_measured_out_of_vocabulary_value(self):
        src = next(s for s in dv.ALERT_SOURCES if s["table"] == "notice")
        sev = src["severity"].lower()
        for raw in ("'error'", "'notification'", "'informational (default)'"):
            assert raw in sev, f"notice does not fold {raw}"
        assert "else 'unknown'" in sev, "an unrecognised severity must stay visible"

    def test_the_emitted_alerts_sql_only_contains_valid_severities(self):
        """The whole point: a consumer filtering severity IN ('critical','high') must
        not silently miss rows."""
        sql = dv.build_alerts_sql(DB, _catalog())
        valid = {"critical", "high", "medium", "low", "informational", "unknown"}
        emitted = set(re.findall(r"THEN '([a-z][a-z ()]*)'", sql))
        assert emitted <= valid, f"out-of-vocabulary severities emitted: {emitted - valid}"


class TestDiscovery:
    def test_uid_lookup_includes_every_uid_bearing_table(self):
        cat = _catalog(brand_new_protocol=_COMMON)
        sql = dv.build_uid_lookup_sql(DB, cat)
        for t in ("conn", "dns", "weird", "suricata_corelight", "brand_new_protocol"):
            assert f"{DB}.{t}" in sql, f"{t} not discovered"

    def test_a_net_new_log_type_joins_with_no_code_change(self):
        """rdp does not exist yet because that traffic has not been seen. When it
        shows up it must be indexed automatically."""
        before = dv.build_uid_lookup_sql(DB, _catalog())
        after = dv.build_uid_lookup_sql(DB, _catalog(rdp=_COMMON))
        assert f"{DB}.rdp" not in before
        assert f"{DB}.rdp" in after
        assert after.count("UNION ALL") == before.count("UNION ALL") + 1

    def test_tables_without_the_key_are_excluded(self):
        sql = dv.build_uid_lookup_sql(DB, _catalog())
        assert f"{DB}.corelight_ml_metrics" not in sql

    def test_operational_rollups_are_excluded(self):
        cat = _catalog(suricata_stats=_COMMON, reporter=_COMMON)
        sql = dv.build_uid_lookup_sql(DB, cat)
        assert f"{DB}.suricata_stats" not in sql
        assert f"{DB}.reporter" not in sql

    def test_fuid_lookup_discovers_all_fuid_bearing_tables(self):
        sql = dv.build_fuid_lookup_sql(DB, _catalog())
        # notice and yara carry fuid too; the old hand-made view only had files
        assert f"{DB}.notice" in sql
        assert f"{DB}.yara_corelight" in sql

    def test_log_type_is_labelled_so_a_session_is_readable(self):
        sql = dv.build_uid_lookup_sql(DB, _catalog())
        assert "'conn' AS log_type" in sql


class TestDDL:
    def test_emits_create_or_replace_for_each_view(self):
        ddl = dv.build_view_ddl(DB, _catalog())
        assert set(ddl) == {"alerts", "uid_lookup", "fuid_lookup"}
        for view, sql in ddl.items():
            assert sql.startswith(f"CREATE OR REPLACE VIEW {DB}.{view} AS")

    def test_empty_catalog_yields_no_ddl_rather_than_broken_sql(self):
        assert dv.build_view_ddl(DB, {}) == {}

    def test_partition_column_is_projected(self):
        """Every source is dt-partitioned; without dt the views cannot be pruned
        and every query would scan the whole dataset."""
        for sql in dv.build_view_ddl(DB, _catalog()).values():
            assert "dt AS dt" in sql


class TestAnomalyRealSchema:
    """The anomaly log's real shape broke three assumptions. Lock each fix."""

    def _sql(self):
        return dv.build_alerts_sql(DB, _catalog(anomaly=_ANOMALY_COLS))

    def test_included_with_the_real_schema(self):
        assert f"{DB}.anomaly" in self._sql()

    def test_host_cidr_suffix_is_stripped(self):
        """original_entity is '172.27.0.137/32'. ipscope.is_in_scope parses bare
        addresses, so '10.220.40.7/32' returns False even for an in-scope host:
        passing the CIDR through would silently redact every anomaly row."""
        assert "REGEXP_EXTRACT(original_entity, '^([^/]+)')" in self._sql()

    def test_assoc_entities_array_is_not_projected(self):
        """row_in_scope scans every value on a row. item_assoc_entities is ~400
        CIDRs that are nearly all out of scope, so projecting it would drop 100%
        of anomaly rows from the feed."""
        assert "item_assoc_entities" not in self._sql()

    def test_score_is_bucketed_not_passed_through(self):
        sql = self._sql()
        assert "TRY_CAST(item_score AS DOUBLE) >= 0.9" in sql

    def test_sensor_ignorable_flag_is_honoured(self):
        assert "COALESCE(ignorable, false) = false" in self._sql()

    def test_detail_carries_the_human_sentence_and_the_offender(self):
        sql = self._sql()
        assert "use_case_description" in sql
        assert "observed=" in sql

    def test_an_override_referencing_a_missing_column_skips_the_branch(self):
        """If the sensor renames original_entity, that branch must drop rather
        than make the whole alerts view fail to build."""
        cols = _ANOMALY_COLS - {"original_entity"}
        sql = dv.build_alerts_sql(DB, _catalog(anomaly=cols))
        assert f"{DB}.anomaly" not in sql
        assert sql.count("UNION ALL") == 3


class TestFiveAlertTypes:
    def test_all_five_configured_sources(self):
        """suri, notice, yara, ml, anomaly."""
        got = {s["alert_type"] for s in dv.ALERT_SOURCES}
        assert got == {"suricata", "notice", "ml", "yara", "anomaly"}
