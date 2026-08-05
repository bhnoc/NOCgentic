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


@pytest.mark.parametrize("label,module,caller", AGENTS)
def test_confidence_fence_is_stripped_from_the_answer(label, module, caller, monkeypatch):
    """The fence is parsed into `confidence` and the UI renders that as a bar.
    Regression: it used to survive in `answer` too, so formatAnswer() rendered
    it a second time as a literal trailing code block — '{"confidence": 0.95}'
    visible in the chat bubble under the real answer text."""
    good = '## Answer\nClear finding.\n```json\n{"confidence": 0.95}\n```'
    answer, confidence = caller(module, good, monkeypatch)
    assert confidence == pytest.approx(0.95), f"{label}: sanity check on the fixture"
    assert "confidence" not in answer, f"{label}: fence text leaked into the answer: {answer!r}"
    assert "```" not in answer, f"{label}: fence markers leaked into the answer: {answer!r}"
    assert "Clear finding." in answer, f"{label}: stripping the fence must not eat real content"


def _make_raising_llm(exc: Exception):
    async def _fake(*args, **kwargs):
        raise exc
    return _fake


@pytest.mark.parametrize("label,module,attr", [
    ("alert-triage.llm_triage", _at, "llm_triage"),
    ("athena-hunter.llm_analyze", _ah, "llm_analyze"),
    ("thousandeyes.llm_analyze", _te, "llm_analyze"),
])
def test_llm_call_failure_does_not_leak_raw_data_json(label, module, attr, monkeypatch):
    """When the LLM call itself fails (provider down, RuntimeError from a
    missing key, etc.), the old fallback text embedded a raw json.dumps() of
    the query/triage/monitoring payload straight into the operator-facing
    answer — internal detail nobody asked for, and it read as a broken
    product rather than a real (if degraded) response. Must be a plain retry
    message with no JSON structure in it."""
    monkeypatch.setattr(module, "llm_complete", _make_raising_llm(RuntimeError("no API key")))
    if attr == "llm_triage":
        answer, confidence = asyncio.run(module.llm_triage("test query", {"alerts": []}))
    else:
        ctx = {"query_results": [], "errors": [], "total_rows": 0, "total_query_time_ms": 0} \
            if module is _ah else {"total_tests": 0, "degraded_tests": []}
        answer, confidence = asyncio.run(module.llm_analyze("test query", ctx))
    assert confidence == pytest.approx(LOW), label
    assert answer == "There was an issue calling the model. Please try again.", \
        f"{label}: expected the plain retry message, got {answer!r}"
    assert "{" not in answer and "}" not in answer, f"{label}: raw JSON leaked: {answer!r}"


def test_llm_triage_no_fence_replaces_the_garbled_answer_outright(monkeypatch):
    """alert-triage specifically: a missing fence means the model went off-script
    (ran out of tokens mid-bullet, or wandered into free text like "Let's check
    confidence: 0.95 (data is..." instead of the required fence). What's left in
    `answer` is not trustworthy enough to show, garbled fragment and all — the fix
    replaces it outright with a plain retry message rather than appending a caveat
    onto text the operator shouldn't be reading either way."""
    answer, confidence = _call_triage(
        _at, "Let's check confidence: 0.95 (data is incomplete", monkeypatch
    )
    assert confidence == pytest.approx(LOW)
    assert answer == "There was an issue calling the model. Please try again."
