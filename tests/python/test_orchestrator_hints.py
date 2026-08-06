"""Regression: Next Steps hints must never be schema/SQL introspection text.

Bug report: hints occasionally surfaced something like "show tables in
blackhatnoc_glue" instead of a domain follow-up ("all sessions/connections for
IP X"). Root cause traced to a failed Athena query leaking its catalog-
qualified engine error into the answer text that generate_hints() summarizes
(fixed separately in athena-hunter/main.py::_scrub_engine_error). This test
locks in the orchestrator's own defense-in-depth filter, _strip_schema_noise,
which drops any schema/SQL-shaped hint regardless of which upstream agent
produced it.
"""

import importlib.util
import os
import sys

import pytest

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(_ROOT, "agents", "shared"))


@pytest.fixture(scope="module")
def orch_mod():
    path = os.path.join(_ROOT, "agents", "orchestrator", "main.py")
    spec = importlib.util.spec_from_file_location("orchestrator_main_hints", path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:
        pytest.skip(f"orchestrator deps unavailable: {exc}")
    return mod


class TestStripSchemaNoise:
    def test_drops_show_tables_hint(self, orch_mod):
        hints = [
            "show tables in blackhatnoc_glue",
            "Show all connections for this IP in the last 24h",
        ]
        result = orch_mod._strip_schema_noise(hints)
        assert result == ["Show all connections for this IP in the last 24h"]

    def test_drops_glue_database_name_even_without_show_tables(self, orch_mod):
        hints = ["Check blackhatnoc_glue for related sessions"]
        assert orch_mod._strip_schema_noise(hints) == []

    def test_drops_information_schema_and_sql_error_language(self, orch_mod):
        hints = [
            "Query information_schema for related tables",
            "Investigate the COLUMN_NOT_FOUND error further",
            "Find top talkers by bytes transferred today",
        ]
        assert orch_mod._strip_schema_noise(hints) == [
            "Find top talkers by bytes transferred today"
        ]

    def test_legitimate_domain_hints_survive_untouched(self, orch_mod):
        hints = [
            "Show all connections for this IP in the last 24h",
            "Query DNS logs for suspicious domains in the last 24h",
            "Find top talkers by bytes transferred today",
            "Check SSL/TLS connections to unusual server names",
            "Search alerts for high-severity events this week",
        ]
        assert orch_mod._strip_schema_noise(hints) == hints


class TestStripZoneAssetNoise:
    """Live-caught bug: hints surfaced raw filter syntax naming internal
    segments, e.g. "search src_ip=Switch-AP_Mgmt dst_ip=Tool_Mgmt over last 7d"
    and "stat sum(bytes) by src_ip, dst_ip where zone=AI_Cyber_Bootcamp".
    _ZONE_RE only substitutes the literal words "Registration"/"Tools" in
    place, so it never saw these — they're LLM-paraphrased/invented
    underscore-joined identifiers in the same naming shape as the real
    restricted segment "Tool Mgmt" (docs/DATA-SCHEMA.md), not that literal
    word. _strip_zone_asset_noise drops the whole hint instead, matching
    _strip_vendor_names / _strip_schema_noise's reject-the-candidate pattern.
    """

    def test_drops_the_live_caught_hints(self, orch_mod):
        hints = [
            "search src_ip=Switch-AP_Mgmt dst_ip=Tool_Mgmt over last 7d",
            "stat sum(bytes) by src_ip, dst_ip where zone=AI_Cyber_Bootcamp",
            "Show all connections for this IP in the last 24h",
        ]
        assert orch_mod._strip_zone_asset_noise(hints) == [
            "Show all connections for this IP in the last 24h"
        ]

    def test_drops_raw_key_equals_value_filter_syntax(self, orch_mod):
        hints = ["Investigate host=10.220.5.12 further"]
        assert orch_mod._strip_zone_asset_noise(hints) == []

    def test_drops_underscore_joined_identifiers_regardless_of_content(self, orch_mod):
        """Not name-specific: any zone/asset-shaped token is dropped, so a
        label the LLM invents (not just ones we've already seen) is caught."""
        hints = ["Check the Some_Other_Segment for lateral movement"]
        assert orch_mod._strip_zone_asset_noise(hints) == []

    def test_legitimate_domain_hints_survive_untouched(self, orch_mod):
        hints = [
            "Show all connections for this IP in the last 24h",
            "Query DNS logs for suspicious domains in the last 24h",
            "Find top talkers by bytes transferred today",
            "Check SSL/TLS connections to unusual server names",
            "Search alerts for high-severity events this week",
        ]
        assert orch_mod._strip_zone_asset_noise(hints) == hints


class TestZoneReCatchesLiteralSegmentNames:
    """Live-caught regression (QA sweep 10): the LLM used the real,
    space-separated segment name "Tool Mgmt" (docs/DATA-SCHEMA.md) verbatim
    in Next Steps hints instead of paraphrasing it into an underscore-joined
    identifier. _strip_zone_asset_noise's underscore/filter-syntax heuristics
    never see a plain space-separated real name, so _ZONE_RE itself (which
    sanitize_output_text runs on every hint) has to catch the literal names,
    not just the bare words "Registration"/"Tools" it originally matched.
    """

    def test_catches_live_leaked_tool_mgmt_hints(self, orch_mod):
        leaked = [
            "pivot to Tool Mgmt zone outbound HTTP user agents",
            "investigate authentication failures from Tool Mgmt",
            "filter proxy logs for PyCurl and Go-http-client user agents in Tool Mgmt",
            "review network flows for data exfiltration from the Tool Mgmt zone",
        ]
        for hint in leaked:
            scrubbed = orch_mod.sanitize_output_text(hint)
            assert "Tool Mgmt" not in scrubbed
            assert "internal" in scrubbed.lower()

    def test_catches_other_real_infrastructure_segment_names(self, orch_mod):
        assert "Registration Hypervisors" not in orch_mod.sanitize_output_text(
            "unusual traffic from Registration Hypervisors"
        )
        assert "Umbrella DNS Virtual Appliances" not in orch_mod.sanitize_output_text(
            "check the OpenDNS/Umbrella DNS Virtual Appliances logs"
        )

    def test_does_not_false_trigger_on_singular_tool(self, orch_mod):
        # "attack tool" (singular, generic English) must survive untouched.
        text = "the attacker used a custom attack tool"
        assert orch_mod.sanitize_output_text(text) == text
