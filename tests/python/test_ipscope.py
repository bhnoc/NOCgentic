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
    is_in_scope,
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
