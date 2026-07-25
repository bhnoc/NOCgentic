"""
Confidence-fallback regression (sweep-4/5 ql-1 / ql-2 / ql-3).

Each agent asks the LLM to end its answer with a ```json {"confidence": 0.XX}```
fence and parses it out. The FIX: when that fence is MISSING or the value is
malformed, the agent must fall back to a LOW sentinel (~0.3), NOT the old
fake-high default (0.7/0.75). A truncated/garbled answer must not report high
confidence to the operator.

We exercise the REAL extraction path by monkeypatching each module's
`llm_complete` to return a canned answer, then calling the real llm_analyze /
llm_triage and asserting on the returned confidence. The regex + default block
under test is the actual code in main.py.
"""

from __future__ import annotations

import asyncio

import pytest

from conftest import load_agent_main

_at = load_agent_main("alert-triage", "alert_triage_main")
_ah = load_agent_main("athena-hunter", "athena_hunter_main")
_te = load_agent_main("thousandeyes-analyst", "te_main")

LOW = 0.3


def _make_fake_llm(answer: str):
    async def _fake(*args, **kwargs):
        return answer
    return _fake


# (module, coroutine-factory) for each agent's confidence-extracting function.
def _call_triage(module, answer, monkeypatch):
    monkeypatch.setattr(module, "llm_complete", _make_fake_llm(answer))
    return asyncio.run(module.llm_triage("test query", {"alerts": []}))


def _call_hunter(module, answer, monkeypatch):
    monkeypatch.setattr(module, "llm_complete", _make_fake_llm(answer))
    ctx = {"query_results": [], "errors": [], "total_rows": 0, "total_query_time_ms": 0}
    return asyncio.run(module.llm_analyze("test query", ctx))


def _call_te(module, answer, monkeypatch):
    monkeypatch.setattr(module, "llm_complete", _make_fake_llm(answer))
    ctx = {"total_tests": 0, "degraded_tests": []}
    return asyncio.run(module.llm_analyze("test query", ctx))


AGENTS = [
    ("alert-triage.llm_triage", _at, _call_triage),
    ("athena-hunter.llm_analyze", _ah, _call_hunter),
    ("thousandeyes.llm_analyze", _te, _call_te),
]


@pytest.mark.parametrize("label,module,caller", AGENTS)
def test_missing_confidence_fence_yields_low(label, module, caller, monkeypatch):
    """No ```json{"confidence":..}``` fence at all -> LOW sentinel.

    REVERT-CHECK: the pre-fix default was a HIGH value (0.7 / 0.75). If reverted,
    `confidence = 0.75` before the regex, a missing fence leaves it high, and
    this assertion (~0.3) FAILS.
    """
    answer, confidence = caller(module, "## Answer\nSomething happened. No fence here.", monkeypatch)
    assert confidence == pytest.approx(LOW), f"{label}: missing fence should give ~0.3, got {confidence}"


@pytest.mark.parametrize("label,module,caller", AGENTS)
def test_malformed_confidence_value_yields_low(label, module, caller, monkeypatch):
    """A fence present but with a non-numeric value -> LOW (regex won't match a
    number, so it takes the default branch)."""
    bad = '## Answer\nStuff.\n```json\n{"confidence": "high"}\n```'
    answer, confidence = caller(module, bad, monkeypatch)
    assert confidence == pytest.approx(LOW), f"{label}: malformed value should give ~0.3, got {confidence}"


@pytest.mark.parametrize("label,module,caller", AGENTS)
def test_valid_confidence_fence_is_parsed(label, module, caller, monkeypatch):
    """A well-formed high-confidence fence IS honored (proves the LOW default
    is a fallback, not a hard cap; the test isn't trivially always-0.3)."""
    good = '## Answer\nClear finding.\n```json\n{"confidence": 0.92}\n```'
    answer, confidence = caller(module, good, monkeypatch)
    assert confidence == pytest.approx(0.92), f"{label}: valid fence should parse, got {confidence}"


@pytest.mark.parametrize("label,module,caller", AGENTS)
def test_confidence_clamped_to_unit_interval(label, module, caller, monkeypatch):
    over = '## Answer\nx\n```json\n{"confidence": 5.0}\n```'
    answer, confidence = caller(module, over, monkeypatch)
    assert 0.0 <= confidence <= 1.0
    assert confidence == pytest.approx(1.0)
