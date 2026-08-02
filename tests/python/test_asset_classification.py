"""Gates for batch asset classification (lambda/asset_classification.py).

Ported from PostCog's per-IP profiler. Two real bugs surfaced on the first run
against live data and are locked here, because both produced confident wrong
answers rather than errors:

  1. 'cros' is a substring of "Microsoft-CryptoAPI", so Windows hosts were
     reported as ChromeOS.
  2. An OS rule with no device-rule counterpart set os_name but left device_type
     'unknown', which reads as missing data instead of a missing rule.

The non-UA sources (software, dhcp host_name) that lifted coverage from ~1.5% to
~24% multiply both of those risks -- more rules, matched against strings that are
product names and people's names rather than structured UAs -- so they carry the
same substring gates plus provenance and fan-out gates of their own.

DHCP option-55 (dhcp_fp_lite.prl) then took in-scope coverage 44% -> 59% and adds a
third failure mode on top of those two: it is keyed on MAC, not ip, so it needs a
bridge that can fan out in both directions. TestDhcpPrlSignal and TestPrlColumnGating
gate all three -- substring (',1,3,6' is a prefix of ',1,3,60'), precedence (a family
must never displace a version), and fan-out (one row per ip, always).
"""

import os
import re
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

# `software` keys on `host`, a VARCHAR ip -- NOT id_orig_h, and `host` is a Trino
# reserved word. Both facts are load-bearing; see TestSoftwareSignal.
_SOFTWARE = {
    "ts_datetime", "ts", "host", "host_p", "software_type", "name",
    "version_major", "version_minor", "version_minor2", "version_minor3",
    "version_addl", "unparsed_version", "dt",
}


# dhcp_fp_lite is EXACTLY these columns -- no ip anywhere, which is the whole
# integration problem the `fpr` CTE exists to solve. See TestDhcpPrlSignal.
_FP_LITE = {"ts_datetime", "mac", "prl", "dt"}


def _catalog(**extra):
    cat = {
        "conn": _CONN,
        "known_devices": {"host_ip", "mac", "vendor_mac", "dt"},
        "dhcp": {"assigned_addr", "mac", "host_name", "dt"},
        "http": {"id_orig_h", "user_agent", "dt"},
        "ssl": {"id_orig_h", "server_name", "dt"},
        "software": _SOFTWARE,
    }
    cat.update(extra)
    return cat


def _catalog_prl(**extra):
    """_catalog() plus dhcp_fp_lite.

    Deliberately a SEPARATE helper. Adding dhcp_fp_lite to the shared catalog would
    change the COALESCE string the existing precedence tests assert on, and those
    tests encode real incidents -- they should keep testing the three-tier contract
    they were written for. The PRL tier asserts its own precedence below.
    """
    cat = _catalog(dhcp_fp_lite=_FP_LITE)
    cat.update(extra)
    return cat


def _cte(sql, alias):
    """The text of one CTE, so a gate can assert about that source alone."""
    marker = f"\n{alias} AS ("
    start = sql.index(marker) if marker in sql else sql.index(f"WITH {alias} AS (")
    tail = sql[start:]
    depth = 0
    for i, ch in enumerate(tail):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return tail[:i + 1]
    raise AssertionError(f"CTE {alias} is unterminated")


def _apply(rules, value):
    """Evaluate a normalized rule table the way the generated SQL does.

    Same order, same anchor semantics ('^' means LIKE 'needle%'), so a rule that
    passes here is a rule the CASE agrees with. Duplicating the matcher would let
    the test drift from the SQL.
    """
    for needle, label in rules:
        if needle.startswith("^"):
            if value.startswith(needle[1:]):
                return label
        elif needle in value:
            return label
    return None


def _sw_norm(name: str) -> str:
    """Mirror of _SW_NORM's REGEXP_REPLACE, in Python."""
    return " " + re.sub("[^a-z0-9]+", " ", name.lower()) + " "


def _host_norm(hostname: str) -> str:
    """Mirror of _HOST_NORM."""
    return "-" + re.sub("[^a-z0-9]+", "-", hostname.lower()) + "-"


def _sw_os(name: str):
    return _apply(ac._SOFTWARE_OS_RULES, _sw_norm(name))


def _sw_device(name: str):
    return _apply(ac._SOFTWARE_DEVICE_RULES, _sw_norm(name))


def _dhcp_os(hostname: str):
    return _apply(ac._DHCP_OS_RULES, _host_norm(hostname))


def _dhcp_device(hostname: str):
    return _apply(ac._DHCP_DEVICE_RULES, _host_norm(hostname))


def _prl_norm(prl: str) -> str:
    """Mirror of _PRL_NORM: strip anything that is not a digit or comma, pad with
    commas so every needle can carry its own boundary at both ends."""
    return "," + re.sub("[^0-9,]+", "", prl) + ","


def _prl_os(prl: str):
    return _apply(ac._PRL_OS_RULES, _prl_norm(prl))


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
        assert ddl.startswith(f"CREATE TABLE {DB}.asset_classification_2026_08_01")
        assert "\nAS\n" in ddl

    def test_ctas_omits_external_location_by_default(self):
        """The show workgroup sets EnforceWorkGroupConfiguration, which rejects a
        CTAS that names its own output path."""
        assert "external_location" not in ac.build_ctas(DB, DATE, _catalog())

    def test_ctas_can_pin_a_location_when_the_workgroup_allows_it(self):
        ddl = ac.build_ctas(DB, DATE, _catalog(), "s3://bucket/prefix/")
        assert "external_location = 's3://bucket/prefix/'" in ddl

    def test_table_name_helper_matches_the_ctas_target(self):
        """The Lambda uses table_name() to find and drop the previous build, so a
        mismatch would silently orphan tables."""
        assert ac.table_name(DATE) == "asset_classification_2026_08_01"
        assert ac.table_name(DATE) in ac.build_ctas(DB, DATE, _catalog())

    def test_ctas_is_none_when_unsatisfiable(self):
        assert ac.build_ctas(DB, DATE, {}) is None

    def test_dominant_user_agent_is_chosen_not_an_arbitrary_one(self):
        """A host runs a browser plus a dozen app agents; the most-used one is the
        best OS signal."""
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog())
        assert "ROW_NUMBER() OVER (PARTITION BY id_orig_h ORDER BY COUNT(*) DESC)" in sql


class TestManagementTooling:
    def test_known_mdm_and_edr_vendors_are_matched(self):
        """By TELEMETRY domain, not vendor name. crowdstrike.com is deliberately
        absent -- see test_vendor_marketing_traffic_is_not_management_tooling."""
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog())
        for domain in ("jamfcloud.com", "cloudsink.net", "manage.microsoft.com"):
            assert domain in sql, f"{domain} is not matched"

    def test_the_needles_are_boundary_anchored(self):
        """A bare '%crowdstrike%' matched crowdstrikeinc.demdex.net -- ADOBE AD
        TRACKING -- plus www./go./ir.crowdstrike.com, all measured on dt=2026-08-02.
        Each was setting mgmt_tooling ("someone's IT owns this device") for a person
        browsing a vendor booth. Same class as 'cros' matching Microsoft-CryptoAPI."""
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog())
        for needle in ("crowdstrike", "carbonblack", "jamf", "kandji", "intune",
                       "1password", "duosecurity", "netskope"):
            assert f"LIKE '%{needle}%'" not in sql, (
                f"'%{needle}%' is an unanchored substring")
        for domain in ac._MGMT_SNI:
            assert f"LIKE '%.{domain}'" in sql, f"{domain} is not anchored on a dot"

    def test_vendor_marketing_traffic_is_not_management_tooling(self):
        """The Black Hat problem: thousands of people browse vendor websites here.
        crowdstrike.com proves nothing about the host; cloudsink.net proves the Falcon
        sensor is running. tool_taxonomy makes the same call for security_tools."""
        assert "cloudsink.net" in ac._MGMT_SNI
        for marketing in ("crowdstrike.com", "sentinelone.com", "carbonblack.com",
                          "microsoft.com", "demdex.net"):
            assert marketing not in ac._MGMT_SNI, f"{marketing} is booth browsing"

    @pytest.mark.parametrize("sni,managed", [
        # Real agent telemetry -> managed.
        ("ts01-b.cloudsink.net", True),
        ("bhnoc.jamfcloud.com", True),
        ("agents.manage.microsoft.com", True),
        ("web-api.kandji.io", True),
        # Booth browsing and lookalikes -> NOT managed.
        ("crowdstrikeinc.demdex.net", False),
        ("www.crowdstrike.com", False),
        ("go.crowdstrike.com", False),
        ("ir.crowdstrike.com", False),
        ("m365.cloud.microsoft", False),
    ])
    def test_the_matcher_agrees_with_the_measured_traffic(self, sni, managed):
        """Reimplements the emitted predicate: exact domain or a dotted subdomain."""
        hit = any(sni == d or sni.endswith("." + d) for d in ac._MGMT_SNI)
        assert hit is managed, f"{sni} -> managed={hit}, expected {managed}"

    def test_mgmt_is_not_treated_as_a_threat_signal(self):
        """It says someone's IT owns the device, which changes how a finding on it
        is triaged. It is context, not a detection."""
        assert "mgmt_tooling" in ac.build_asset_classification_sql(DB, DATE, _catalog())


class TestSoftwareSignal:
    """`software` is the coverage win: 2,929 hosts against 270 with a UA."""

    def test_software_cte_keys_on_double_quoted_host(self):
        """`host` is a VARCHAR ip and the ONLY key on this table. Joining on
        id_orig_h parses fine and returns an all-null column, so the regression is
        silent. It is also a Trino reserved word, and backticks are DDL-only."""
        sw = _cte(ac.build_asset_classification_sql(DB, DATE, _catalog()), "sw")
        assert '"host" AS ip' in sw
        assert 'GROUP BY "host"' in sw
        assert "id_orig_h" not in sw
        assert "`host`" not in sw

    def test_software_aggregates_before_the_join(self):
        """~5 rows per host. Joined raw it would multiply every host's row."""
        sw = _cte(ac.build_asset_classification_sql(DB, DATE, _catalog()), "sw")
        assert "MIN_BY(sw_os" in sw
        assert "GROUP BY ip" in sw

    def test_software_join_cannot_fan_out(self):
        """The gate that matters is one row per ip out of every enrichment CTE, not
        the presence of a particular aggregate."""
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog())
        for alias in ("sw", "dh"):
            body = _cte(sql, alias)
            assert "GROUP BY ip" in body or "WHERE rn = 1" in body, alias

    def test_real_os_names_are_resolved(self):
        assert _sw_os("Windows-Update-Agent") == "Windows"
        assert _sw_os("iPhone OS") == "iOS"
        assert _sw_os("Dalvik") == "Android"
        assert _sw_os("Ubuntu") == "Linux"
        assert _sw_device("iPhone OS") == "phone"

    def test_software_needles_do_not_fire_inside_unrelated_products(self):
        """The 'cros' in Microsoft-CryptoAPI bug, replayed against the 310 product
        names this source actually carries. Each pair is (name, forbidden label)."""
        traps = [
            ("Microsoft-CryptoAPI", "ChromeOS"),
            ("biosensor", "iOS"),
            ("Macromedia Flash", "macOS"),
            ("Macromedia", "macOS"),
            ("Kubernetes", "Linux"),
            ("Chrome", "ChromeOS"),
            ("Windows-Update-Agent", "ChromeOS"),
            ("nginx", "Windows"),
            ("Radiosonde", "iOS"),
            ("Cisco-IOS-XE", "macOS"),
        ]
        for name, forbidden in traps:
            assert _sw_os(name) != forbidden, f"{name!r} misclassified as {forbidden}"
            assert _sw_device(name) != forbidden, name

    def test_a_bare_product_name_yields_no_os(self):
        """A browser or web server name says nothing about the OS underneath, and a
        guess there is exactly the confident nonsense this module refuses."""
        for name in ("Chrome", "Firefox", "nginx", "Apache", "OpenSSL"):
            assert _sw_os(name) is None, name

    def test_the_most_specific_rule_wins_not_an_arbitrary_row(self):
        """A host reports several names, so the aggregate must choose by specificity.
        Rule order encodes it, and MIN_BY over the rule index reads that order."""
        sw = _cte(ac.build_asset_classification_sql(DB, DATE, _catalog()), "sw")
        assert "os_rank" in sw and "device_rank" in sw
        assert "MIN_BY(sw_os, os_rank)" in sw

    def test_empty_marker_is_filtered_as_a_value(self):
        """Zeek writes '-' for an absent field and the loader types it as string, so
        NULL-checking alone lets '-' through as a real name."""
        sw = _cte(ac.build_asset_classification_sql(DB, DATE, _catalog()), "sw")
        assert "name NOT IN ('', '-')" in sw


class TestDhcpHostnameSignal:
    """2,557 IPs. Weakest source: the string is whatever a human typed."""

    def test_vendor_default_hostnames_are_resolved(self):
        assert _dhcp_os("DESKTOP-A1B2C3") == "Windows"
        assert _dhcp_os("Jamess-iPhone") == "iOS"
        assert _dhcp_os("MacBook-Pro") == "macOS"
        assert _dhcp_os("Galaxy-S23") == "Android"
        assert _dhcp_device("Jamess-iPhone") == "phone"
        assert _dhcp_device("iPad-mini") == "tablet"

    def test_hostname_needles_do_not_fire_inside_personal_names(self):
        """Hostnames are mostly PEOPLE'S NAMES, which is a richer trap than product
        names: '-kali' matches "Kalisha-Laptop" and '-win' matches "Darwin-PC"."""
        traps = [
            ("Kalisha-Laptop", "Linux"),
            ("Kalisha-MBP", "Linux"),
            ("Darwin-PC", "Windows"),
            ("Twin-Laptop", "Windows"),
            ("Erwin-Desktop", "Windows"),
            ("biosensor-7", "iOS"),
            ("Maciej-PC", "macOS"),
            ("Pixel-Studio-NAS", "Windows"),
        ]
        for hostname, forbidden in traps:
            assert _dhcp_os(hostname) != forbidden, (
                f"{hostname!r} misclassified as {forbidden}"
            )

    def test_generic_form_factor_words_give_a_device_but_no_os(self):
        """"Kalisha-Laptop" is as likely a MacBook as a ThinkPad. The form factor is
        evidence; the OS is not, unless the name is a vendor default at the front."""
        assert _dhcp_device("Kalisha-Laptop") == "computer"
        assert _dhcp_os("Kalisha-Laptop") is None
        assert _dhcp_os("LAPTOP-9XYZ") == "Windows"

    def test_iot_devices_are_not_claimed_to_have_an_os(self):
        assert _dhcp_device("Chromecast") == "iot"
        assert _dhcp_os("Chromecast") is None

    def test_dominant_hostname_per_ip_not_per_mac(self):
        """Grouping by (mac, ip) gave a reassigned lease two rows for one IP, which
        duplicated that host in the output."""
        dh = _cte(ac.build_asset_classification_sql(DB, DATE, _catalog()), "dh")
        assert "PARTITION BY assigned_addr" in dh
        assert "GROUP BY mac" not in dh

    def test_empty_hostnames_are_excluded(self):
        dh = _cte(ac.build_asset_classification_sql(DB, DATE, _catalog()), "dh")
        assert "host_name NOT IN ('', '-')" in dh


class TestDhcpPrlSignal:
    """DHCP option-55. Measured 2026-08-01: +727 in-scope hosts net of the three
    stronger tiers, 646 of them on RANDOMIZED macs where no vendor hint exists.

    Two things make this tier riskier than the others and both are gated here: it is
    keyed on mac rather than ip and so needs a bridge that can fan out, and its
    values are pure digits and commas so every needle is a substring of some longer
    unrelated one.
    """

    def test_real_signatures_resolve_to_the_measured_family(self):
        """The exact live values, with their measured purity against hosts whose OS
        the stronger tiers already knew (single-mac IPs only)."""
        # 852/886 = 96.2% Apple
        assert _prl_os("1,121,3,6,15,108,114,119,162,252") == "Apple"
        assert _prl_os("1,121,3,6,15,108,114,119,162,252,95,44,46") == "Apple"
        # 753/760 = 99.1% Windows
        assert _prl_os("1,3,6,15,31,33,43,44,46,47,119,121,249,252") == "Windows"
        assert _prl_os("1,3,6,15,31,33,43,44,46,47,119,121,249,252,114") == "Windows"
        # 228/247 = 92.3% Linux
        assert _prl_os("1,2,6,12,15,26,28,121,3,33,40,41,42,119,249,252,17") == "Linux"

    def test_the_ambiguous_signature_is_deliberately_not_claimed(self):
        """',1,3,6,15,26,28,51,58,59,' reads like the obvious Android list, and 71
        Android hosts carry it -- but so do 206 Linux hosts (Chrome on X11). 25%
        purity for Android, 74% for Linux, no clean split. A signature we cannot
        corroborate must not ship, so this one names NOTHING rather than guessing the
        majority label."""
        assert _prl_os("1,3,6,15,26,28,51,58,59,43,114,108") is None
        assert _prl_os("1,3,6,15,26,28,51,58,59,43") is None

    def test_no_android_is_claimed_from_prl_at_all(self):
        """Consequence of the above, made explicit so a future edit that adds an
        Android rule has to argue with a test. The only Android-looking list on this
        network is 74% Linux."""
        assert "Android" not in {label for _, label in ac._PRL_OS_RULES}

    def test_an_unrecognized_list_is_not_a_guess(self):
        for prl in ("1,3,6,12,15,28,42,43", "1,3,28,6", "1,3", "26,1,28,3,15,6,7"):
            assert _prl_os(prl) is None, prl

    def test_a_shorter_signature_does_not_match_a_longer_number(self):
        """THE PRL SUBSTRING TRAP. '1,3,6' is a substring of '11,3,6' and of
        '1,3,60', so a naive LIKE '%1,3,6%' fires on unrelated signatures. The
        comma padding plus a '^' anchor is what stops it -- without both, every
        assertion here flips."""
        traps = [
            # a longer first option, not option 1 at all
            ("11,121,3,6,15,108,114,119,162,252", "Apple"),
            # 47 became 470: a different option, must not match the Windows prefix
            ("1,3,6,15,31,33,43,44,46,470,119,121,249,252", "Windows"),
            # 121 became 1210
            ("1,2,6,12,15,26,28,1210,3,33,40", "Linux"),
            # the signature appears, but NOT at the start -- it is a different client
            ("99,1,121,3,6,15,108,114,119,162,252", "Apple"),
            ("55,1,3,6,15,31,33,43,44,46,47,119", "Windows"),
        ]
        for prl, forbidden in traps:
            assert _prl_os(prl) != forbidden, f"{prl!r} misclassified as {forbidden}"

    def test_every_prl_needle_is_anchored_and_comma_delimited(self):
        """Structural, so it fires on a rule added later without a gate. A PRL needle
        must be anchored at the front AND carry commas at both ends: unanchored it
        matches mid-list, and without the trailing comma ',1,3,6' matches ',1,3,60'."""
        for needle, _ in ac._PRL_OS_RULES:
            assert needle.startswith("^,"), f"{needle!r} is not anchored at a comma"
            assert needle.endswith(","), f"{needle!r} has no trailing comma"

    def test_prl_never_claims_an_os_version(self):
        """Option-55 cannot distinguish an iPhone from a MacBook, or Windows 10 from
        11. Every label must be a FAMILY. 'macOS' or 'iOS' here would let the weakest
        tier out-specify the strongest ones."""
        families = {"Apple", "Windows", "Linux", "Android", "ChromeOS"}
        versioned = {"iOS", "iPadOS", "macOS", "tvOS", "Windows NT", "Ubuntu", "Debian"}
        for _, label in ac._PRL_OS_RULES:
            assert label in families, f"{label!r} is not an OS family"
            assert label not in versioned, f"{label!r} claims more than a family"

    def test_prl_contributes_no_device_type(self):
        """An OS family is not a form factor: 'Apple' spans an iPhone and a Mac Pro,
        'Linux' a laptop and a Raspberry Pi. So the device table is empty on purpose
        and device_source can never read 'dhcp_prl' -- confirmed against live data."""
        assert ac._PRL_DEVICE_RULES == ()
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog_prl())
        block = sql[sql.index("AS device_type"):sql.index("AS device_source")]
        assert "prl" not in block
        assert "'dhcp_prl'" not in sql[sql.index("AS device_type"):
                                       sql.index("AS device_source") + 40]

    def test_prl_is_the_lowest_precedence_tier(self):
        """The whole contract. PRL gives a family, so it must only ever fill a NULL
        the three stronger tiers left -- never displace 'iOS' with 'Apple'."""
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog_prl())
        assert ("COALESCE(ua.ua_os, sw.sw_os, dhh.dhcp_os, fpr.prl_os, 'unknown') "
                "AS os_name") in sql

    def test_prl_provenance_is_tested_after_every_stronger_source(self):
        """A source column that can name a signal which did not produce the value
        launders inference as evidence. Same order as the COALESCE, or it lies."""
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog_prl())
        block = sql[sql.index("AS os_name"):sql.index("AS os_source")]
        assert (block.index("ua.ua_os") < block.index("sw.sw_os")
                < block.index("dhh.dhcp_os") < block.index("fpr.prl_os"))

    def test_os_source_names_dhcp_prl_when_it_wins(self):
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog_prl())
        assert "WHEN fpr.prl_os IS NOT NULL THEN 'dhcp_prl'" in sql

    def test_the_bridge_is_dhcp_not_known_devices(self):
        """dhcp_fp_lite carries NO ip, so it needs a mac->ip bridge. Measured on
        2026-08-01: dhcp.assigned_addr reached 3,151 in-scope IPs against
        known_devices.host_ip's 3,095, unioning the two added zero, and dhcp is the
        DHCP server's own record of who held the address rather than a second
        inference. Using both would add a fan-out surface for no coverage."""
        fpr = _cte(ac.build_asset_classification_sql(DB, DATE, _catalog_prl()), "fpr")
        assert "assigned_addr AS ip" in fpr
        assert "l.mac = f.mac" in fpr
        assert "known_devices" not in fpr
        assert "host_ip" not in fpr

    def test_the_bridge_collapses_on_both_sides_before_joining(self):
        """FAN-OUT IS REAL ON BOTH SIDES: one mac held up to 7 addresses in the day,
        one address was held by up to 3 macs, and 151 IPs bridge to more than one
        distinct PRL. So the fingerprint collapses per mac FIRST, then the bridged
        result collapses per ip. Joining either side raw duplicates hosts -- exactly
        the bug the `dh` CTE already had once."""
        fpr = _cte(ac.build_asset_classification_sql(DB, DATE, _catalog_prl()), "fpr")
        assert "PARTITION BY mac ORDER BY COUNT(*) DESC" in fpr
        assert "PARTITION BY l.ip" in fpr
        assert fpr.count("WHERE rn = 1") == 2

    def test_the_dominant_prl_per_ip_is_chosen_not_an_arbitrary_one(self):
        """151 in-scope IPs bridge to more than one PRL. ARBITRARY() there would make
        the OS of those hosts depend on Athena's scan order."""
        fpr = _cte(ac.build_asset_classification_sql(DB, DATE, _catalog_prl()), "fpr")
        assert "ORDER BY SUM(l.leases) DESC" in fpr
        assert "ARBITRARY(" not in fpr

    def test_empty_markers_are_filtered_on_both_sides(self):
        """Zeek writes '-' for an absent field, so NULL-checking alone lets '-'
        through as a mac to join on -- which would bridge every unfingerprinted host
        to every unleased one."""
        fpr = _cte(ac.build_asset_classification_sql(DB, DATE, _catalog_prl()), "fpr")
        assert fpr.count("mac NOT IN ('', '-')") == 2
        assert "prl NOT IN ('', '-')" in fpr
        assert "assigned_addr NOT IN ('', '-')" in fpr

    def test_prl_does_not_count_toward_confidence(self):
        """It is the weakest tier, it names a family not an OS, and it comes from the
        very same DHCP conversation the hostname already scored for. Counting it
        would lift ~3,100 hosts a confidence tier on one option-55 list."""
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog_prl())
        assert "fpr.prl_os IS NOT NULL THEN 1" not in sql

    def test_sql_normalizes_prl_before_matching(self):
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog_prl())
        assert "REGEXP_REPLACE(f.prl, '[^0-9,]+', '')" in sql

    def test_normalization_strips_junk_and_pads(self):
        """The live delimiter is a bare comma with no spaces, verified against real
        values. Stripping non-digits means a future sensor build that starts emitting
        "1, 3, 6" does not silently stop matching."""
        assert _prl_norm("1,121,3,6,15") == ",1,121,3,6,15,"
        assert _prl_norm("1, 121, 3") == ",1,121,3,"
        assert _prl_os("1, 121, 3, 6, 15, 108") == "Apple"


class TestPrlColumnGating:
    """dhcp_fp_lite is a newer table than the rest and needs TWO tables' columns to
    be useful. One failed statement loses the whole hourly rebuild, so every one of
    these must degrade to no PRL tier rather than to broken SQL."""

    def test_absent_table_degrades_to_no_prl_tier(self):
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog())
        assert f"{DB}.dhcp_fp_lite" not in sql
        assert "prl_os" not in sql
        assert "'dhcp_prl'" not in sql
        # and the column shape is untouched
        assert "AS os_name" in sql and "AS os_source" in sql

    def test_table_without_prl_column_is_skipped(self):
        sql = ac.build_asset_classification_sql(
            DB, DATE, _catalog_prl(dhcp_fp_lite={"ts_datetime", "mac", "dt"}))
        assert f"{DB}.dhcp_fp_lite" not in sql
        assert "prl_os" not in sql

    def test_table_without_mac_column_is_skipped(self):
        """No mac means no bridge, so the prl is unusable even though it is present."""
        sql = ac.build_asset_classification_sql(
            DB, DATE, _catalog_prl(dhcp_fp_lite={"ts_datetime", "prl", "dt"}))
        assert f"{DB}.dhcp_fp_lite" not in sql

    def test_dhcp_without_mac_kills_the_bridge_not_the_query(self):
        """The bridge needs dhcp.mac. Gating only on dhcp_fp_lite's own columns would
        emit a join against a column that does not exist -- a hard Athena failure."""
        sql = ac.build_asset_classification_sql(
            DB, DATE, _catalog_prl(dhcp={"assigned_addr", "host_name", "dt"}))
        assert f"{DB}.dhcp_fp_lite" not in sql
        assert "prl_os" not in sql
        # the hostname tier is independent and must survive
        assert "dhh.dhcp_os" in sql

    def test_prl_alone_still_classifies(self):
        """No http, no software: PRL must carry os_name by itself, since it is the
        one tier that does not need the host to emit anything identifying."""
        sql = ac.build_asset_classification_sql(DB, DATE, {
            "conn": _CONN,
            "dhcp": {"assigned_addr", "mac", "dt"},
            "dhcp_fp_lite": _FP_LITE,
        })
        assert "COALESCE(fpr.prl_os, 'unknown') AS os_name" in sql
        assert "WHEN fpr.prl_os IS NOT NULL THEN 'dhcp_prl'" in sql
        # no hostname column on dhcp here, so that tier must be absent
        assert "dhcp_os" not in sql

    def test_no_unbound_alias_in_any_prl_catalog_combination(self):
        """A dangling alias is a hard Athena failure, which costs the whole rebuild.
        Same gate as the three-tier version, replayed across the PRL permutations."""
        for cat in (
            _catalog_prl(),
            {"conn": _CONN, "dhcp": {"assigned_addr", "mac", "dt"},
             "dhcp_fp_lite": _FP_LITE},
            _catalog_prl(dhcp_fp_lite={"ts_datetime", "mac", "dt"}),
            _catalog_prl(dhcp={"assigned_addr", "host_name", "dt"}),
        ):
            sql = ac.build_asset_classification_sql(DB, DATE, cat)
            tail = sql[sql.rindex("\nSELECT\n"):]
            select, _, from_clause = tail.partition("\nFROM hosts h")
            bound = {"h"} | {b or a for a, b in
                             re.findall(r"JOIN (\w+)(?: (\w+))? ON", from_clause)}
            used = set(re.findall(r"\b(\w+)\.\w+", select))
            dangling = used - bound
            assert not dangling, f"unbound aliases {dangling} for catalog {sorted(cat)}"

    def test_prl_partition_is_pinned(self):
        fpr = _cte(ac.build_asset_classification_sql(DB, DATE, _catalog_prl()), "fpr")
        assert fpr.count(f"dt = '{DATE}'") == 2


class TestNormalizationIsWhatMakesNeedlesSafe:
    def test_delimiters_are_baked_in_by_normalizing_not_per_rule(self):
        """Every needle relies on the value being lowercased and its
        non-alphanumerics collapsed to one delimiter, with the whole value padded.
        Without the padding, a needle written ' cros ' could never match a name that
        IS "CrOS"."""
        assert _sw_norm("Microsoft-CryptoAPI") == " microsoft cryptoapi "
        assert _sw_norm("CrOS") == " cros "
        assert _host_norm("DESKTOP-A1B2C3") == "-desktop-a1b2c3-"

    def test_sql_normalizes_before_matching(self):
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog())
        assert "REGEXP_REPLACE(LOWER(name), '[^a-z0-9]+', ' ')" in sql
        assert "REGEXP_REPLACE(LOWER(hostname), '[^a-z0-9]+', '-')" in sql

    def test_every_new_needle_is_delimited_or_anchored(self):
        """A needle with no boundary at either end is the 'cros' bug waiting to
        happen. Structural, so it fires on a rule added later without a gate."""
        tables = {
            "_SOFTWARE_OS_RULES": (ac._SOFTWARE_OS_RULES, " "),
            "_SOFTWARE_DEVICE_RULES": (ac._SOFTWARE_DEVICE_RULES, " "),
            "_DHCP_OS_RULES": (ac._DHCP_OS_RULES, "-"),
            "_DHCP_DEVICE_RULES": (ac._DHCP_DEVICE_RULES, "-"),
            # Digits-and-commas values, where the trap is arithmetic rather than
            # lexical: ',1,3,6' is a prefix of ',1,3,60'. Same invariant, comma
            # delimiter. See TestDhcpPrlSignal for the anchoring half.
            "_PRL_OS_RULES": (ac._PRL_OS_RULES, ","),
        }
        for name, (rules, delim) in tables.items():
            for needle, _ in rules:
                body = needle[1:] if needle.startswith("^") else needle
                assert body.startswith(delim), f"{name}: {needle!r} has no leading delimiter"

    def test_os_and_device_rule_tables_stay_in_sync(self):
        """Same invariant as the UA tables: an OS needle with no device counterpart
        sets os_name and leaves device_type 'unknown', which reads as a data gap.
        The reverse IS allowed -- a ThinkPad is a computer of unknown OS."""
        # _PRL_OS_RULES is EXEMPT and that is deliberate: an OS family is not a form
        # factor, so option-55 yields os_name and no device_type at all. Enforcing the
        # invariant there would force a phone-vs-computer guess out of a signal that
        # cannot make one. TestDhcpPrlSignal locks the empty table instead.
        for os_rules, dev_rules, label in (
            (ac._SOFTWARE_OS_RULES, ac._SOFTWARE_DEVICE_RULES, "software"),
            (ac._DHCP_OS_RULES, ac._DHCP_DEVICE_RULES, "dhcp"),
        ):
            dev = {n for n, _ in dev_rules}
            missing = [n for n, _ in os_rules if n not in dev]
            assert not missing, f"{label} OS needles with no device rule: {missing}"


class TestPrecedenceAndProvenance:
    def test_user_agent_wins_over_both_weaker_sources(self):
        """A UA is a direct claim by the client stack. software is observed, a DHCP
        hostname is typed by a human. COALESCE order is the whole contract."""
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog())
        assert "COALESCE(ua.ua_os, sw.sw_os, dhh.dhcp_os, 'unknown') AS os_name" in sql
        assert ("COALESCE(ua.ua_device, sw.sw_device, dhh.dhcp_device, 'unknown') "
                "AS device_type") in sql

    def test_ua_unknown_is_nulled_so_a_weaker_source_can_fill_it(self):
        """Without NULLIF, the UA rules' 'unknown' is a value and COALESCE stops
        there -- every host with any UA would be permanently unknown, which is the
        exact ceiling this work exists to lift."""
        ua = _cte(ac.build_asset_classification_sql(DB, DATE, _catalog()), "ua")
        assert "NULLIF(" in ua
        assert ", 'unknown') AS ua_os" in ua
        assert ", 'unknown') AS ua_device" in ua

    def test_provenance_columns_exist(self):
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog())
        assert "AS os_source" in sql
        assert "AS device_source" in sql

    def test_provenance_values_are_the_documented_set(self):
        """A consumer filters on these, so the vocabulary is a contract."""
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog())
        for value in ("'user_agent'", "'software'", "'dhcp_hostname'", "'unknown'"):
            assert value in sql, value

    def test_provenance_is_tested_in_the_same_order_as_the_value(self):
        """A source column that could name a signal which did not produce the value
        is worse than no source column: it launders inference as evidence."""
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog())
        block = sql[sql.index("AS os_name"):sql.index("AS os_source")]
        assert block.index("ua.ua_os") < block.index("sw.sw_os") < block.index("dhh.dhcp_os")

    def test_provenance_is_unknown_when_no_signal_landed(self):
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog())
        assert "ELSE 'unknown'\n     END AS os_source" in sql

    def test_provenance_still_exists_with_no_platform_sources_at_all(self):
        """The column set must not depend on the catalog, or a consumer's query
        breaks on the day a source is late."""
        sql = ac.build_asset_classification_sql(DB, DATE, {"conn": _CONN})
        assert "'unknown' AS os_source" in sql
        assert "'unknown' AS device_source" in sql

    def test_confidence_counts_software_but_not_a_dhcp_platform_guess(self):
        """A DHCP hostname already scores once for existing. Counting a guess
        derived from it again would climb every DHCP host a tier on one weak
        signal counted twice."""
        sql = ac.build_asset_classification_sql(DB, DATE, _catalog())
        assert "CASE WHEN sw.sw_os IS NOT NULL THEN 1 ELSE 0 END" in sql
        assert "dhh.dhcp_os IS NOT NULL THEN 1" not in sql


class TestPartialCatalogGatesOnColumns:
    """One failed statement loses the whole hourly rebuild, so a table that exists
    without the column being read must not make it into the SQL."""

    def test_software_without_name_is_skipped_entirely(self):
        sql = ac.build_asset_classification_sql(
            DB, DATE, _catalog(software={"host", "dt"}))
        assert f"{DB}.software" not in sql
        assert "sw.sw_os" not in sql

    def test_software_without_host_is_skipped_entirely(self):
        sql = ac.build_asset_classification_sql(
            DB, DATE, _catalog(software={"name", "dt"}))
        assert f"{DB}.software" not in sql

    def test_dhcp_without_host_name_is_skipped_entirely(self):
        sql = ac.build_asset_classification_sql(
            DB, DATE, _catalog(dhcp={"assigned_addr", "mac", "dt"}))
        assert "dhcp_os" not in sql
        assert "CAST(NULL AS VARCHAR) AS hostname" in sql

    def test_missing_software_leaves_the_column_shape_intact(self):
        cat = _catalog()
        del cat["software"]
        sql = ac.build_asset_classification_sql(DB, DATE, cat)
        assert "AS os_name" in sql and "AS os_source" in sql
        assert f"{DB}.software" not in sql

    def test_software_alone_still_classifies(self):
        """No http and no dhcp: software must carry os_name on its own, since on
        this network it reaches 10x the hosts a UA does."""
        sql = ac.build_asset_classification_sql(
            DB, DATE, {"conn": _CONN, "software": _SOFTWARE})
        assert "COALESCE(sw.sw_os, 'unknown') AS os_name" in sql
        assert "WHEN sw.sw_os IS NOT NULL THEN 'software'" in sql
        assert "user_agent" not in sql.split("AS os_source")[0].split("AS os_name")[1]

    def test_no_source_claims_a_column_it_did_not_join(self):
        """Every alias referenced in the SELECT must have a LEFT JOIN behind it. A
        dangling alias is a hard Athena failure, which costs the whole rebuild."""
        for cat in (
            _catalog(),
            {"conn": _CONN, "software": _SOFTWARE},
            {"conn": _CONN, "dhcp": {"assigned_addr", "host_name", "dt"}},
            _catalog(software={"host", "dt"}),
        ):
            sql = ac.build_asset_classification_sql(DB, DATE, cat)
            tail = sql[sql.rindex("\nSELECT\n"):]
            select, _, from_clause = tail.partition("\nFROM hosts h")
            bound = {"h"} | {b or a for a, b in
                             re.findall(r"JOIN (\w+)(?: (\w+))? ON", from_clause)}
            used = set(re.findall(r"\b(\w+)\.\w+", select))
            dangling = used - bound
            assert not dangling, f"unbound aliases {dangling} for catalog {sorted(cat)}"


class TestJa3IsDeliberatelyNotAnOsSignal:
    def test_no_ja3_to_os_lookup_table_exists(self):
        """7,358 IPs carry a ja3, but the top fingerprint alone spans 1,401 of them.
        Without a curated mapping a ja3 cannot name an OS, and inventing one would
        produce exactly the confident nonsense the module docstring forbids."""
        sql = ac.build_asset_classification_sql(
            DB, DATE, _catalog(ssl={"id_orig_h", "server_name", "ja3", "dt"}))
        assert "ja3" not in sql

    def test_the_reasoning_is_recorded_where_the_next_person_will_look(self):
        assert "ja3" in ac.__doc__

