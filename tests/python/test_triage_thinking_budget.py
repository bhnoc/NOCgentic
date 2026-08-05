"""
alert-triage prose-synthesis TRUNCATION regression (sweep-6 ct-10).

Live failure, 2026-08-05, on the exact question the count fix targets:

    Q: "How many alerts in the last 24 hours by severity?"
    A: "There was an issue calling the model. Please try again."   (confidence 0.3)

    llm_client: LLM response truncated (finish_reason=max_tokens,
                max_tokens=4096, output_tokens=4092) model=gemini-3.5-flash-lite
    alert-triage: llm_triage: no confidence trailer in answer, using low default 0.3

The Gemini trace showed `output_token_details: {"reasoning": 3932}` — the model
spent 3932 of its 4096 shared output tokens THINKING, leaving ~160 for a
four-section answer. It stopped mid-bullet, never emitted the
```json{"confidence"}``` fence, and llm_triage (correctly) replaced the garbled
fragment with the retry message. The local lane answered the same query at 0.95.

Cause is the pairing, not the prompt: `thinking_budget=0` is CLAMPED TO -1
(UNBOUNDED dynamic thinking) for flash-lite in llm_client._get_gemini_model,
and Gemini's thinking tokens are drawn from max_output_tokens. Unbounded
thinking + a tight output ceiling = reasoning starves the prose. This repo has
already been bitten by this twice and fixed it the same way both times
(athena-hunter SQL gen, orchestrator llm_classify): bound the thinking to a
fixed positive budget and give the output real room.

These tests assert on the ARGUMENTS llm_triage passes, because that pairing is
the defect. Asserting on answer text would be asserting on Gemini's mood.
"""

from __future__ import annotations

import asyncio
import inspect

import pytest

from conftest import load_agent_main

_at = load_agent_main("alert-triage", "alert_triage_main")


def _capture_llm_kwargs(monkeypatch) -> dict:
    """Run the real llm_triage and capture what it asked the provider for."""
    seen: dict = {}

    async def _fake(*args, **kwargs):
        seen.update(kwargs)
        return '## Answer\nfine.\n```json\n{"confidence": 0.9}\n```'

    monkeypatch.setattr(_at, "llm_complete", _fake)
    asyncio.run(_at.llm_triage("How many alerts in the last 24 hours by severity?", {"alerts": []}))
    return seen


def test_thinking_is_bounded_so_it_cannot_starve_the_prose(monkeypatch):
    """REVERT-CHECK: pre-fix this call passed thinking_budget=0, which
    _get_gemini_model rewrites to -1 (unbounded) on any flash-lite model. With
    thinking sharing max_output_tokens, an unbounded budget can consume ~96% of
    it (3932/4096 observed live) and truncate the answer into a hard failure."""
    kw = _capture_llm_kwargs(monkeypatch)
    tb = kw.get("thinking_budget")
    assert tb is not None, "llm_triage must state a thinking budget explicitly"
    assert tb > 0, (
        f"thinking_budget={tb!r} means UNBOUNDED dynamic thinking on flash-lite "
        "(0 is clamped to -1), and thinking tokens come out of max_output_tokens. "
        "Pass a fixed positive budget so reasoning cannot starve the answer."
    )


def test_output_budget_leaves_room_for_the_answer_after_thinking(monkeypatch):
    """The prose budget must exceed the thinking budget by enough to actually
    emit the four required sections plus the confidence fence.

    A passing answer for this agent runs ~850 output tokens (the local lane's
    successful run on the failing query was 847), and Key Entities lists can be
    a dozen bullets. Require at least 2048 tokens of headroom beyond thinking.
    """
    kw = _capture_llm_kwargs(monkeypatch)
    max_tokens = kw.get("max_tokens")
    tb = kw.get("thinking_budget")
    assert max_tokens is not None, "llm_triage must state max_tokens explicitly"
    headroom = max_tokens - tb
    assert headroom >= 2048, (
        f"max_tokens={max_tokens} minus thinking_budget={tb} leaves only {headroom} "
        "tokens for prose. The live failure emitted ~160 and truncated mid-bullet, "
        "which the missing-fence path turns into 'There was an issue calling the "
        "model' — a hard failure, not a degraded answer."
    )


def test_the_missing_fence_path_is_still_the_thing_being_protected():
    """Sanity anchor: this whole test file only matters because a truncated
    answer is discarded outright. If that ever changes to a soft caveat, the
    budget invariants above are less critical — but they must not silently
    become dead tests either."""
    src = inspect.getsource(_at.llm_triage)
    assert "There was an issue calling the model" in src
    assert "no confidence trailer" in src


def test_truncation_is_surfaced_in_logs_not_swallowed():
    """The only reason this bug was diagnosable at all: llm_client logs the
    finish_reason. Keep it."""
    import importlib

    llm_client = importlib.import_module("llm_client")
    src = inspect.getsource(llm_client)
    assert 'finish_reason in ("max_tokens", "length")' in src, (
        "llm_client must keep detecting truncated completions; without this "
        "warning a truncated answer looks like a generic model failure"
    )
    assert "LLM response truncated" in src
