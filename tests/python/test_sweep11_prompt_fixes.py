"""Regression: QA sweep 11 prompt-text fixes.

Each of these locks in a rule added to a SYSTEM_PROMPT/SQL_GEN_PROMPT after a
live-caught bug, following this codebase's established pattern
(test_prompt_schema_truth.py, test_sweep10_prompt_fixes.py) of asserting the
guiding text is present rather than re-driving the LLM.
"""

import asyncio
import json

import athena_client as ac
from conftest import load_agent_main

_ah = load_agent_main("athena-hunter", "athena_hunter_main_s11")
_at = load_agent_main("alert-triage", "alert_triage_main_s11")


def _gen_user_content(query="show me activity between 3am and 4am"):
    """Capture the real user_content generate_sql builds, per the pattern in
    test_local_day_windowing.py — the clock-time rule lives in the per-call
    user_content, not the static SQL_GEN_PROMPT."""
    captured = {}

    async def fake_llm_complete(system_prompt=None, user_content=None, **kw):
        captured["user"] = user_content
        return json.dumps(["SELECT 1 FROM conn WHERE dt IN ('a') AND ts >= 1 AND ts <= 2"])

    real = _ah.llm_complete
    _ah.llm_complete = fake_llm_complete
    try:
        asyncio.run(_ah.generate_sql(query, {
            "ips": [], "domains": [], "uids": [], "md5s": [], "sha256s": [],
        }, ac.today_partition()))
    finally:
        _ah.llm_complete = real
    return captured["user"]


class TestClockTimeEpochGuidance:
    """S11FF-001: "between 3am and 4am" (a bare clock-time range with no day
    named) had no worked example, so the model computed the wrong epoch
    bounds — off by ~80-95 minutes, and not matching UTC or EVENT_TZ."""

    def test_user_content_has_clock_time_rule(self):
        uc = _gen_user_content()
        assert "bare CLOCK-TIME range" in uc
        assert "3am = 3*3600" in uc


class TestFanOutExcludesUnspecifiedAddress:
    """S11FF-003: '::' (Zeek's IPv6 unspecified-address placeholder) ranked
    as the #1 host by fan-out, ahead of every real host."""

    def test_sql_gen_prompt_excludes_unspecified_addresses(self):
        assert "Fan-out" in _ah.SQL_GEN_PROMPT
        assert "'::', '0.0.0.0'" in _ah.SQL_GEN_PROMPT


class TestNegationUsesNotExists:
    """S11FF-005: 'which hosts never triggered an alert' used a null-unsafe
    NOT IN (subquery) against alerts.orig_h, which is genuinely NULL for some
    alert sources (e.g. anomaly detections) — NOT IN against any NULL row
    silently returns zero results regardless of the true answer."""

    def test_correctness_checks_require_not_exists_for_negation(self):
        assert "NOT EXISTS" in _ah.SQL_GEN_PROMPT
        assert "NOT IN" in _ah.SQL_GEN_PROMPT
        assert "null-safe" in _ah.SQL_GEN_PROMPT


class TestZoneRowsMustBeSummed:
    """S11FF-002: three genuinely distinct restricted-infrastructure zones
    all redact to the display string "internal", and the answer cited only
    the largest of the three same-labeled rows, undercounting by ~18%."""

    def test_system_prompt_requires_summing_restricted_zone_rows(self):
        assert "SUM every restricted-infrastructure row" in _ah.SYSTEM_PROMPT


class TestAlertTriageCorrelationRequiresFlowData:
    """S11FF-006: a hint asking to 'correlate traffic spikes with security
    events' routed to alert-triage, which answered with a completed-sounding
    Risk/Verdict line while its own flows_returned_for_analysis and
    dns_returned_for_analysis were both zero — no correlation was actually
    performed."""

    def test_system_prompt_requires_disclosing_no_correlation(self):
        assert "no flow/DNS correlation performed" in _at.SYSTEM_PROMPT
