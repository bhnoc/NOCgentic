"""Gates for batch asset classification (lambda/asset_classification.py).

Ported from PostCog's per-IP profiler. Two real bugs surfaced on the first run
against live data and are locked here, because both produced confident wrong
answers rather than errors:

  1. 'cros' is a substring of "Microsoft-CryptoAPI", so Windows hosts were
     reported as ChromeOS.
  2. An OS rule with no device-rule counterpart set os_name but left device_type
     'unknown', which reads as missing data instead of a missing rule.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lambda"))

import asset_classification as ac  # noqa: E402

DB = "testdb"
DATE = "2026-08-01"

_CONN = {
    "id_orig_h", "id_resp_h", "orig_bytes", "resp_bytes", "ts_datetime",
    "id_orig_network_name", "id_resp_network_name", "id_orig_room_name",
    "id_resp_room_name", "dt",
}


def _catalog(**extra):
    cat = {
        "conn": _CONN,
        "known_devices": {"host_ip", "mac", "vendor_mac", "dt"},
        "dhcp": {"assigned_addr", "mac", "host_name", "dt"},
        "http": {"id_orig_h", "user_agent", "dt"},
        "ssl": {"id_orig_h", "server_name", "dt"},
    }
    cat.update(extra)
    return cat


def _os_of(ua: str) -> str:
    low = ua.lower()
    return next((label for needle, label in ac._OS_RULES if needle in low), "unknown")


def _device_of(ua: str) -> str:
    low = ua.lower()
    return next((label for needle, label in ac._DEVICE_RULES if needle in low), "unknown")


class TestUserAgentSubstringTraps:
    """Real UA strings pulled from the live network."""

    def test_microsoft_cryptoapi_is_not_chromeos(self):
        """'cros' inside 'Microsoft-CryptoAPI' reported ChromeOS on a Windows box."""
        assert _os_of("Microsoft-CryptoAPI/10.0") == "Windows"

    def test_real_chromeos_still_detected(self):
        """The narrowed needle must not break the case it exists for."""
        assert _os_of("Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36") == "ChromeOS"

    def test_ios_beats_macintosh(self):
        """iOS UAs say 'like Mac OS X'; order decides this."""
        ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15"
        assert _os_of(ua) == "iOS"
        assert _device_of(ua) == "phone"

    def test_ipad_is_a_tablet_not_a_phone(self):
        ua = "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15"
        assert _os_of(ua) == "iPadOS"
        assert _device_of(ua) == "tablet"

    def test_macos_desktop(self):
        ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        assert _os_of(ua) == "macOS"
        assert _device_of(ua) == "computer"

    def test_command_line_tools_are_classed_as_tools(self):
        for ua in ("curl/8.7.1", "Wget/1.21", "python-requests/2.31.0"):
            assert _device_of(ua) == "tool", ua

    def test_unrecognized_ua_is_unknown_not_a_guess(self):
        """A wrong confident answer is worse than 'unknown' in an asset inventory."""
        assert _os_of("SomeVendorAgent/4.2 (proprietary)") == "unknown"


class TestRuleTablesStayInSync:
    def test_every_os_needle_has_a_device_counterpart(self):
        """An OS rule without a device rule yields os_name set and device_type
        'unknown', which looks like a data gap but is a rule-table gap."""
        os_needles = [n for n, _ in ac._OS_RULES]
        dev_needles = {n for n, _ in ac._DEVICE_RULES}
        missing = [n for n in os_needles if n not in dev_needles]
        assert not missing, f"OS needles with no device rule: {missing}"

    def test_no_needle_matches_inside_a_known_unrelated_agent(self):
        """The real property, not a length heuristic: no needle may fire on a UA
        that belongs to a different platform. 'cros' matching Microsoft-CryptoAPI
        is the bug this locks out; a short needle like 'ipad' is fine because
        nothing unrelated contains it."""
        # (agent string, the OS label it must NOT be classified as)
        traps = [
            ("Microsoft-CryptoAPI/10.0", "ChromeOS"),
            ("Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.0", "ChromeOS"),
            ("com.apple.trustd/3.0", "ChromeOS"),
            ("Debian APT-HTTP/1.3 (2.6.1)", "Windows"),
            ("Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36", "Linux"),
        ]
        for agent, forbidden in traps:
            assert _os_of(agent) != forbidden, (
                f"{agent!r} misclassified as {forbidden}"
            )


class TestSQLGeneration:
    def test_returns_none_without_the_spine_table(self):
        """conn is every host that talked. No conn, no classification."""
        assert ac.build_asset_classification_sql(DB, DATE, {"http": {"user_agent"}}) is None

    def test_counts_both_traffic_directions(self):
        """A responder-only host (a booth box that only receives) has zero rows as
        id_orig_h; filtering one direction reported it as absent entirely."""
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog())
        assert "id_orig_h AS ip" in sql
        assert "id_resp_h AS ip" in sql

    def test_byte_columns_are_try_cast(self):
        """Byte columns are VARCHAR in this catalog and Zeek writes '-' for empty,
        so a direct SUM returns nothing at all."""
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog())
        assert "TRY_CAST(orig_bytes AS DOUBLE)" in sql
        assert "TRY_CAST(resp_bytes AS DOUBLE)" in sql

    def test_missing_enrichment_source_degrades_to_null(self):
        """A partial catalog must still classify traffic, not fail."""
        cat = {"conn": _CONN}
        sql = ac.build_asset_classification_sql(DB, DATE, cat)
        assert sql is not None
        assert "CAST(NULL AS VARCHAR) AS mac" in sql
        assert "'unknown' AS os_name" in sql
        assert f"{DB}.http" not in sql

    def test_randomized_mac_detection(self):
        """Locally-administered bit set means the second hex char is 2/6/a/e. This
        explains an unknown vendor as privacy behaviour, not missing data."""
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog())
        assert "('2','6','a','e')" in sql

    def test_confidence_reflects_signals_that_actually_landed(self):
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog())
        assert "AS confidence" in sql
        assert "'high'" in sql and "'medium'" in sql and "'low'" in sql

    def test_partition_is_pinned_so_a_run_cannot_scan_everything(self):
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog())
        assert f"dt = '{DATE}'" in sql
        assert sql.count(f"dt = '{DATE}'") >= 3

    def test_ctas_names_a_per_day_table(self):
        ddl = ac.build_ctas(DB, DATE, _catalog())
        assert ddl.startswith(f"CREATE TABLE {DB}.asset_classification_2026_08_01 AS")

    def test_ctas_is_none_when_unsatisfiable(self):
        assert ac.build_ctas(DB, DATE, {}) is None

    def test_dominant_user_agent_is_chosen_not_an_arbitrary_one(self):
        """A host runs a browser plus a dozen app agents; the most-used one is the
        best OS signal."""
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog())
        assert "ROW_NUMBER() OVER (PARTITION BY id_orig_h ORDER BY COUNT(*) DESC)" in sql


class TestManagementTooling:
    def test_known_mdm_and_edr_vendors_are_matched(self):
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog())
        for vendor in ("jamf", "crowdstrike", "intune"):
            assert vendor in sql

    def test_mgmt_is_not_treated_as_a_threat_signal(self):
        """It says someone's IT owns the device, which changes how a finding on it
        is triaged. It is context, not a detection."""
        assert "mgmt_tooling" in ac.build_asset_classification_sql(DB, DATE, _catalog())
