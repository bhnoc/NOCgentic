"""
UNBOUNDED-THINKING truncation regression across every Gemini prose call
(sweep-6 ct-10, extended to the sibling agents).

`thinking_budget=0` reads like "don't think". It is not. llm_client's
_get_gemini_model REWRITES 0 to -1 for any *flash-lite* model:

    if thinking_budget == 0 and "flash-lite" in model_name:
        thinking_budget = -1      # -1 == UNBOUNDED dynamic thinking

and Gemini draws thinking tokens from the SAME max_output_tokens pool as the
visible answer. So `0` actually means "let reasoning eat as much of my output
budget as it wants", and when it eats enough the answer truncates mid-sentence.

Every agent here then treats a truncated answer as a total loss, so the operator
gets nothing usable:
  - alert-triage / thousandeyes: no ```json{"confidence"}``` fence -> the answer
    is DISCARDED and replaced with "There was an issue calling the model."
  - orchestrator hints: nothing parseable survives -> _parse_hints returns [] and
    every call silently falls back to static _fallback_hints.

First observed live on alert-triage (2026-08-05): 3932 reasoning tokens of a
4096 budget, ~160 left for a four-section answer. Then measured directly against
the live provider from inside the deployed containers for the other three sites,
using a demanding synthesis prompt at each site's real budget:

    site                       tb=0 (before)                tb>0 (after)
    deter        (2.5-lite)    max_tokens 2/2, ~300 chars   clean 2/2 (needed 2090!)
    thousandeyes (3.5-lite)    max_tokens 1/2, no fence     clean 2/2
    orch-hints   (3.5-lite)    max_tokens 2/2, ~120 chars   clean 2/2
    athena-hunter(3.5-lite)    clean 2/2 but 3911/4096 used clean 2/2 (2124 used)

5 of 6 pre-fix runs produced worthless output; 6 of 6 post-fix runs were clean.
deter needed 2090 output tokens on a clean run, ABOVE its old 2048 ceiling, so
raising the ceiling was required, not precautionary.

athena-hunter is included on margin rather than on an observed failure: it did
not truncate, but it spent 95% of its ceiling (3911 of 4096) to emit ~2000
characters, leaving under 200 tokens of headroom. Bounding thinking also HALVED
its usage (3911 -> 2124) for equivalent output, so the fix is cheaper too.

Note this repo has been bitten by the same pairing four separate times now
(athena-hunter SQL gen, orchestrator llm_classify, alert-triage synthesis, and
these three) and the remedy has been identical every time: a FIXED positive
thinking budget so reasoning cannot starve output, plus real room for the prose.

These tests assert on the ARGUMENTS each call passes, because that pairing IS
the defect. Asserting on answer text would be asserting on Gemini's mood.
"""

from __future__ import annotations

import asyncio
import inspect

import pytest

from conftest import load_agent_main

_at = load_agent_main("alert-triage", "alert_triage_main")
_de = load_agent_main("deter", "deter_main")
_te = load_agent_main("thousandeyes-analyst", "te_budget_main")
_or = load_agent_main("orchestrator", "orch_budget_main")
_ah = load_agent_main("athena-hunter", "athena_hunter_main")


def _capture(module, invoke) -> dict:
    """Run the real function with llm_complete stubbed, capturing its kwargs."""
    seen: dict = {}

    async def _fake(*args, **kwargs):
        seen.update(kwargs)
        # Shaped so each caller's post-processing succeeds and we reach the end.
        return '## Answer\nfine.\n- pivot on 10.0.0.1\n```json\n{"confidence": 0.9}\n```'

    orig = module.llm_complete
    module.llm_complete = _fake
    try:
        asyncio.run(invoke(module))
    finally:
        module.llm_complete = orig
    return seen


async def _call_triage(m):
    await m.llm_triage("How many alerts in the last 24 hours by severity?", {"alerts": []})


async def _call_deter(m):
    await m.llm_deter("who is scanning me", {})


async def _call_te(m):
    await m.llm_analyze("which tests are degraded", {"total_tests": 0, "degraded_tests": []})


async def _call_hints(m):
    await m.generate_hints("show me alerts", "Some answer text.", "alert-triage")


async def _call_hunter(m):
    await m.llm_analyze("top talkers on 443", {
        "query_results": [], "errors": [], "total_rows": 0, "total_query_time_ms": 0})


# (label, module, invoker, minimum prose headroom required after thinking)
#
# Headroom = max_tokens - thinking_budget, i.e. what is left for visible text in
# the worst case where thinking spends its whole allowance. Thresholds are set
# from the MEASURED clean-run output above with margin, not from taste:
#   alert-triage ~850 observed, deter 2090 observed, hints ~450 observed.
SITES = [
    ("alert-triage.llm_triage",  _at, _call_triage, 2048),
    ("deter.llm_deter",          _de, _call_deter,  2048),
    ("thousandeyes.llm_analyze", _te, _call_te,     2048),
    ("orchestrator.generate_hints", _or, _call_hints, 1024),
    ("athena-hunter.llm_analyze", _ah, _call_hunter, 2048),
]


@pytest.mark.parametrize("label,module,invoke,_headroom", SITES)
def test_thinking_is_bounded_so_it_cannot_starve_the_prose(label, module, invoke, _headroom):
    """REVERT-CHECK: every one of these sites passed thinking_budget=0 before,
    which _get_gemini_model rewrites to -1 (unbounded) on flash-lite. Measured
    live, that truncated the answer on 5 of 6 runs."""
    kw = _capture(module, invoke)
    tb = kw.get("thinking_budget")
    assert tb is not None, f"{label}: must state a thinking budget explicitly"
    assert tb > 0, (
        f"{label}: thinking_budget={tb!r} means UNBOUNDED dynamic thinking on "
        "flash-lite (0 is clamped to -1), and thinking tokens come out of "
        "max_output_tokens. Pass a fixed positive budget so reasoning cannot "
        "starve the answer."
    )


@pytest.mark.parametrize("label,module,invoke,headroom", SITES)
def test_output_budget_leaves_room_for_the_answer_after_thinking(label, module, invoke, headroom):
    """The prose budget must survive thinking spending its full allowance.

    deter is the cautionary case: a clean run needed 2090 output tokens while its
    ceiling was 2048, so it could not have completed even with zero thinking.
    """
    kw = _capture(module, invoke)
    max_tokens, tb = kw.get("max_tokens"), kw.get("thinking_budget")
    assert max_tokens is not None, f"{label}: must state max_tokens explicitly"
    actual = max_tokens - tb
    assert actual >= headroom, (
        f"{label}: max_tokens={max_tokens} minus thinking_budget={tb} leaves only "
        f"{actual} tokens for prose (need >= {headroom}, from measured clean runs). "
        "Too little and the answer truncates mid-sentence, which these agents "
        "discard outright rather than showing."
    )


@pytest.mark.parametrize("label,module,invoke,_h", SITES)
def test_no_site_relies_on_the_zero_clamp(label, module, invoke, _h):
    """Belt-and-braces on the whole class: nothing may pass the sentinel that
    triggers the clamp, on any provider. A future model rename could move a site
    off 'flash-lite' and change the meaning of 0 again."""
    kw = _capture(module, invoke)
    assert kw.get("thinking_budget") != 0, (
        f"{label}: thinking_budget=0 is the exact value llm_client rewrites to "
        "unbounded. State the real budget you want."
    )


def test_the_clamp_that_causes_this_still_behaves_as_documented():
    """Pin the surprising behavior itself. If someone makes 0 mean 0, these
    budget tests become belt-and-braces rather than load-bearing — but nobody
    should discover that by accident."""
    import importlib

    llm_client = importlib.import_module("llm_client")
    src = inspect.getsource(llm_client._get_gemini_model)
    assert 'if thinking_budget == 0 and "flash-lite" in model_name:' in src, (
        "the 0->-1 clamp moved or changed; re-derive the budgets in this file "
        "against the live provider before trusting them"
    )
    assert "thinking_budget = -1" in src


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


@pytest.mark.parametrize("label,module,attr", [
    ("alert-triage", _at, "llm_triage"),
    ("thousandeyes", _te, "llm_analyze"),
])
def test_a_truncated_answer_is_still_discarded_not_shown(label, module, attr):
    """Sanity anchor: the budget invariants above only matter because a truncated
    answer is a TOTAL loss to the operator. If that ever softens to a caveat,
    revisit the thresholds — but do not let these tests quietly go dead."""
    src = inspect.getsource(getattr(module, attr))
    assert "There was an issue calling the model" in src, label


def test_orchestrator_hints_falls_back_silently_on_truncation():
    """The hints failure mode is different and quieter: no exception, no visible
    error, just static fallback hints forever. Documented here so the next reader
    knows why hints needed the same fix despite never showing an error."""
    src = inspect.getsource(_or.generate_hints)
    assert "_fallback_hints" in src
    assert "_parse_hints" in src
