"""Gate for the IP scope allowlist (agents/shared/ipscope.py).

Locks the policy: in-scope conference subnets and public addresses are shown,
every other private address is redacted. Includes the exact regression that
prompted this work (10.0.1.63 -> "[INTERNAL-IP].63").
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "agents"))

from shared.ipscope import (  # noqa: E402
    OUT_OF_SCOPE_PLACEHOLDER,
    IN_SCOPE_NETWORKS,
    filter_rows,
    is_conference_network,
    is_in_scope,
    prefix_is_out_of_scope,
    redact_obj,
    redact_text,
    row_in_scope,
)


class TestSubnetParsing:
    def test_expected_subnet_count(self):
        # 1 half-range + 42 (31-72) + 74 (74-147) + 1 v4 /18
        assert len(IN_SCOPE_NETWORKS) == 118

    def test_thirty_is_a_half_range_not_a_slash24(self):
        assert is_in_scope("10.220.30.127")
        assert not is_in_scope("10.220.30.128")
        assert not is_in_scope("10.220.30.200")

    def test_seventy_three_is_excluded_by_design(self):
        assert is_in_scope("10.220.72.10")
        assert not is_in_scope("10.220.73.10")
        assert is_in_scope("10.220.74.10")

    def test_upper_boundary(self):
        assert is_in_scope("10.220.147.9")
        assert not is_in_scope("10.220.148.9")

    def test_192_168_slash18_spans_128_to_191(self):
        assert not is_in_scope("192.168.127.255")
        assert is_in_scope("192.168.128.0")
        assert is_in_scope("192.168.150.20")
        assert is_in_scope("192.168.191.255")
        assert not is_in_scope("192.168.192.0")


class TestPolicy:
    @pytest.mark.parametrize("addr", ["8.8.8.8", "45.83.193.150", "185.220.101.45", "1.1.1.1"])
    def test_public_addresses_are_shown(self, addr):
        """Threat actors / C2 / intel must stay visible."""
        assert is_in_scope(addr)

    @pytest.mark.parametrize(
        "addr",
        [
            "10.0.1.63",        # the original bug report
            "10.0.1.47",
            "10.220.12.5",      # previously "restricted" octet
            "10.220.199.5",
            "172.16.5.9",
            "192.168.1.7",
            "127.0.0.1",        # loopback
            "169.254.169.254",  # EC2 IMDS — must never surface
            "100.64.0.1",       # CGNAT is not public
        ],
    )
    def test_out_of_scope_private_is_redacted(self, addr):
        assert not is_in_scope(addr)

    def test_unparseable_defaults_to_denied(self):
        assert not is_in_scope("not-an-ip")
        assert not is_in_scope("")


class TestRedactText:
    def test_original_bug_no_leaked_octet(self):
        """10.0.1.63 must not degrade to '[INTERNAL-IP].63'."""
        out = redact_text("Show DNS queries made by 10.0.1.63 and 10.0.1.47")
        assert out == (
            f"Show DNS queries made by {OUT_OF_SCOPE_PLACEHOLDER} "
            f"and {OUT_OF_SCOPE_PLACEHOLDER}"
        )
        assert ".63" not in out
        assert ".47" not in out

    def test_no_partial_octet_leak_for_any_private_range(self):
        for addr in ["10.1.2.3", "10.220.12.99", "172.20.1.5", "192.168.0.42"]:
            out = redact_text(f"src={addr} dst=8.8.8.8")
            last_octet = "." + addr.rsplit(".", 1)[1]
            assert last_octet not in out, f"{addr} leaked {last_octet}: {out}"

    def test_in_scope_and_public_survive_together(self):
        text = "10.220.69.5 beaconed to 45.83.193.150"
        assert redact_text(text) == text

    def test_mixed_line(self):
        out = redact_text("flow 10.220.40.7 -> 8.8.8.8 via 10.0.0.9")
        assert out == f"flow 10.220.40.7 -> 8.8.8.8 via {OUT_OF_SCOPE_PLACEHOLDER}"

    def test_non_ip_dotted_numbers_untouched(self):
        assert redact_text("version 1.2.3.400") == "version 1.2.3.400"


class TestRedactTextShapeGapsFound20260805:
    """redact_text() only ever looked for a dotted-quad candidate, so an IPv6
    literal was never even considered for redaction, and a leading-zero IPv4
    (which ipaddress.ip_address() rejects outright as octal-ambiguous) fell
    through the except-ValueError branch as "not a real address" and rendered
    verbatim -- including one inside a restricted subnet."""

    def test_out_of_scope_ipv6_link_local_is_redacted(self):
        out = redact_text("internal host fe80::a00:27ff:fe4e:66a1 talked to 8.8.8.8")
        assert "fe80::" not in out
        assert OUT_OF_SCOPE_PLACEHOLDER in out

    def test_out_of_scope_ipv6_unique_local_is_redacted(self):
        out = redact_text("internal host fc00::1234:5678:9abc talked to 8.8.8.8")
        assert "fc00::" not in out

    def test_public_ipv6_survives(self):
        text = "beaconed to 2001:4860:4860::8888"
        assert redact_text(text) == text

    def test_leading_zero_ipv4_in_restricted_range_is_redacted(self):
        out = redact_text("restricted host 010.220.012.005 talked to 8.8.8.8")
        assert "010.220.012.005" not in out
        assert OUT_OF_SCOPE_PLACEHOLDER in out

    def test_leading_zero_ipv4_in_scope_survives(self):
        text = "conf host 010.220.040.007 talked to 8.8.8.8"
        # 10.220.40.7 (after stripping the zeros) is in scope, so the literal,
        # zero-padded text is left exactly as written -- not renormalized.
        assert redact_text(text) == text

    def test_out_of_range_octet_with_leading_zero_is_not_treated_as_an_ip(self):
        assert redact_text("not an ip 010.220.012.999") == "not an ip 010.220.012.999"

    def test_timestamp_shaped_text_is_not_redacted(self):
        """The IPv6 candidate regex is deliberately broad and can match a
        colon-separated timestamp; ip_address() parsing must reject it."""
        text = "event fired at 12:30:00 sharp"
        assert redact_text(text) == text

    def test_empty_and_none_safe(self):
        assert redact_text("") == ""
        assert redact_text(None) is None


class TestRedactObj:
    def test_nested_structure(self):
        payload = {
            "alerts": [
                {"srcIp": "10.0.1.63", "dstIp": "45.83.193.150", "desc": "hit from 10.0.1.63"},
                {"srcIp": "10.220.55.8", "dstIp": "8.8.8.8"},
            ]
        }
        out = redact_obj(payload)
        assert out["alerts"][0]["srcIp"] == OUT_OF_SCOPE_PLACEHOLDER
        assert out["alerts"][0]["dstIp"] == "45.83.193.150"
        assert "10.0.1.63" not in out["alerts"][0]["desc"]
        assert out["alerts"][1]["srcIp"] == "10.220.55.8"


class TestRowFiltering:
    def test_both_directions_must_qualify(self):
        assert row_in_scope({"id_orig_h": "10.220.40.7", "id_resp_h": "8.8.8.8"})
        # Out-of-scope private source with a legitimate public peer is still not ours.
        assert not row_in_scope({"id_orig_h": "10.0.1.63", "id_resp_h": "8.8.8.8"})
        assert not row_in_scope({"id_orig_h": "10.220.40.7", "id_resp_h": "192.168.1.5"})

    def test_empty_fields_ignored(self):
        assert row_in_scope({"id_orig_h": "10.220.40.7", "id_resp_h": ""})
        assert row_in_scope({"id_orig_h": "10.220.40.7", "id_resp_h": "-"})
        assert row_in_scope({"alert_name": "no addresses here"})

    def test_ui_shaped_fields_checked(self):
        assert not row_in_scope({"srcIp": "10.0.1.63", "dstIp": "8.8.8.8"})

    def test_filter_rows_drops_only_offenders(self):
        rows = [
            {"id_orig_h": "10.220.40.7", "id_resp_h": "8.8.8.8"},
            {"id_orig_h": "10.0.1.63", "id_resp_h": "8.8.8.8"},
            {"id_orig_h": "10.220.147.1", "id_resp_h": "45.83.193.150"},
        ]
        kept = filter_rows(rows)
        assert len(kept) == 2
        assert all(r["id_orig_h"].startswith("10.220.") for r in kept)


class TestOldRegexWouldFail:
    """Proves the gate catches the pre-fix behavior, not just passes vacuously."""

    def test_legacy_shared_suffix_regex_leaked_the_final_octet(self):
        import re

        legacy = re.compile(
            r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"
        )
        assert legacy.sub("[INTERNAL-IP]", "10.0.1.63") == "[INTERNAL-IP].63"
        # The replacement must not.
        assert redact_text("10.0.1.63") == OUT_OF_SCOPE_PLACEHOLDER


class TestRowFilterResistsAliasing:
    """QA sweep: row_in_scope used a fixed column-name allowlist, which aliasing
    defeats. agents/alert-triage/main.py really does `SELECT id_orig_h as ip`."""

    def test_aliased_address_column_still_caught(self):
        assert not row_in_scope({"ip": "10.0.1.63", "connection_count": "4213"})

    def test_arbitrary_alias_caught(self):
        assert not row_in_scope({"host": "10.0.1.63"})
        assert not row_in_scope({"whatever_column_name": "192.168.1.7"})

    def test_ip_embedded_in_free_text_caught(self):
        """A DNS answers column or alert detail can carry an address."""
        assert not row_in_scope({"answers": "resolved to 10.0.0.5", "n": "1"})

    def test_in_scope_aliased_row_still_allowed(self):
        assert row_in_scope({"ip": "10.220.40.7", "connection_count": "9"})

    def test_public_address_allowed_under_any_alias(self):
        assert row_in_scope({"peer": "45.83.193.150"})

    def test_non_string_values_do_not_crash(self):
        assert row_in_scope({"count": 4213, "ratio": 0.5, "flag": None})


class TestPrefixScope:
    def test_fully_out_of_scope_prefixes(self):
        assert prefix_is_out_of_scope("192.168.1")
        assert prefix_is_out_of_scope("10.0")
        assert prefix_is_out_of_scope("172.16")

    def test_in_scope_prefixes_not_blocked(self):
        assert not prefix_is_out_of_scope("10.220.40")
        assert not prefix_is_out_of_scope("10.220")

    def test_public_prefixes_not_blocked(self):
        assert not prefix_is_out_of_scope("45.83.193")

    def test_single_octet_and_full_quad_ignored(self):
        assert not prefix_is_out_of_scope("10")
        assert not prefix_is_out_of_scope("10.0.1.63")


class TestConferenceNetworkOnly:
    """is_conference_network is narrower than is_in_scope: public addresses are
    safe to display but are not the venue, and the alert-feed scope filter
    needs the venue-only question, not the display-safety one."""

    def test_conference_subnet_is_a_conference_network(self):
        assert is_conference_network("10.220.40.7")
        assert is_conference_network("192.168.150.1")

    def test_public_address_is_not_a_conference_network(self):
        assert is_in_scope("45.83.193.150")
        assert not is_conference_network("45.83.193.150")

    def test_out_of_scope_private_address_is_not_a_conference_network(self):
        assert not is_conference_network("10.0.1.63")

    def test_unparseable_input_is_not_a_conference_network(self):
        assert not is_conference_network("not-an-ip")
        assert not is_conference_network("")
