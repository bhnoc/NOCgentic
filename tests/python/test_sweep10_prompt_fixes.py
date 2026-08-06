"""Regression: QA sweep 10 prompt-text fixes.

Each of these locks in a rule added to a SYSTEM_PROMPT/SQL_GEN_PROMPT/
CLASSIFY_SYSTEM_PROMPT after a live-caught bug, following this codebase's
established pattern (test_prompt_schema_truth.py, test_column_synonym_repair.py)
of asserting the guiding text is present rather than re-driving the LLM.
"""

from conftest import load_agent_main

_ah = load_agent_main("athena-hunter", "athena_hunter_main")
_orch = load_agent_main("orchestrator", "orchestrator_main")


class TestWifiSubnetGuidance:
    """FF10-002: 'wifi devices' questions defaulted to a 10.x filter, a range
    with no WiFi clients in it (they live in 192.168.128.0/18)."""

    def test_sql_gen_prompt_names_the_wifi_range(self):
        assert "192.168.128.0/18" in _ah.SQL_GEN_PROMPT
        assert "NEVER 10.x" in _ah.SQL_GEN_PROMPT


class TestExclusivityQueryGuidance:
    """FF10-004: an 'exclusive communication' claim was backed by a query
    pre-filtered to the candidate pair, making the distinct-partner count
    tautologically 1."""

    def test_sql_gen_prompt_has_unrestricted_exclusivity_pattern(self):
        assert "exclusivity questions" in _ah.SQL_GEN_PROMPT
        assert "UNRESTRICTED query" in _ah.SQL_GEN_PROMPT


class TestNextStepsMustBeAnalystAction:
    """FF10-006: Next Steps surfaced SQL-generator-bug language ('Correct the
    type mismatch...') instead of an analyst-actionable step."""

    def test_system_prompt_forbids_query_directed_next_steps(self):
        assert "NEVER an action against the query/SQL/tool itself" in _ah.SYSTEM_PROMPT


class TestConfidenceCapsOnSelfAdmittedMiss:
    """FF10-005: confidence stayed high even when the answer's own text
    admitted the queried window missed the asked-about time."""

    def test_system_prompt_caps_confidence_on_scope_miss(self):
        assert "missing" in _ah.SYSTEM_PROMPT
        assert "scope miss" in _ah.SYSTEM_PROMPT


class TestInternalIpRoutingTiebreaker:
    """FF10-008: a query naming a specific internal IP/CIDR with 'gateway'/
    'route' words was routed to thousandeyes_analyst, which has no per-host
    query capability and answered with an unrelated generic summary."""

    def test_classify_prompt_routes_internal_ip_gateway_queries_to_athena_hunter(self):
        assert "always belongs to athena_hunter" in _orch.CLASSIFY_SYSTEM_PROMPT


class TestUngroundableCapabilityHintFilter:
    """FF10-007: a Next-Steps hint asked to 'verify sensor ingestion', a
    capability athena-hunter (a SQL agent, not a monitoring/heartbeat agent)
    doesn't have, so it answered by redefining the check into something it
    could do (a connection count) rather than refusing the premise."""

    def test_drops_sensor_ingestion_hint(self):
        hints = [
            "Verify sensor ingestion for active connection zones like CISO Boot Camp",
            "Show all connections for this IP in the last 24h",
        ]
        assert _orch._strip_ungroundable_capability_hints(hints) == [
            "Show all connections for this IP in the last 24h"
        ]

    def test_drops_telemetry_and_heartbeat_variants(self):
        assert _orch._strip_ungroundable_capability_hints(
            ["Check telemetry health for the zone"]
        ) == []
        assert _orch._strip_ungroundable_capability_hints(
            ["Confirm sensor heartbeat for this segment"]
        ) == []

    def test_legitimate_hints_survive_untouched(self):
        hints = [
            "Show all connections for this IP in the last 24h",
            "Find top talkers by bytes transferred today",
        ]
        assert _orch._strip_ungroundable_capability_hints(hints) == hints
