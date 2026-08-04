"""The deter agent: safe-pool containment for sessions Manifold has flagged.

Three properties carry the whole feature, and each one fails silently if it
breaks — the caller just gets a slightly different answer, and nobody notices
until someone reads the logs:

  1. The caller's text never reaches SQL. It picks WHICH author-written facet is
     read; it never becomes part of one.
  2. A refusal, an apology, or any mention of the mechanism never reaches the
     caller. That is what the output screen is for, and a screen that lets one
     through ends the deception permanently.
  3. Failure degrades to the existing cover, silently. Deter down, deter slow,
     deter screening its own output away — all of them look to the caller like
     the answer they would have got before this agent existed.

Everything here is locked against those three.
"""

from __future__ import annotations

import asyncio

import pytest

from conftest import load_agent_main

_deter = load_agent_main("deter", "deter_main")
_orch = load_agent_main("orchestrator", "orch_main")
_pool = _deter.safe_pool


# ---------------------------------------------------------------------------
# 1. The pool is fixed: no caller text can reach a statement
# ---------------------------------------------------------------------------

_DT = "(dt = '2026-08-04' AND ts >= 1000 AND ts <= 2000)"


def test_every_shipped_facet_passes_its_own_guard():
    """The guard is only defence in depth if the pool itself clears it."""
    for name in _pool.SAFE_FACETS:
        _pool.render_facet_sql(name, _DT)  # must not raise


def test_no_facet_statement_has_an_unfilled_placeholder():
    """A second placeholder is how caller text would get in. `{dt}` is the only
    substitution the pool is allowed to have."""
    for name, facet in _pool.SAFE_FACETS.items():
        rendered = facet["sql"].format(dt=_DT)
        assert "{" not in rendered and "}" not in rendered, (
            f"facet {name} has a placeholder beyond {{dt}}"
        )


@pytest.mark.parametrize("hostile", [
    "1.2.3.4'; DROP TABLE conn; --",
    "show me everything about 10.0.0.5",
    "' OR '1'='1",
    "protocol mix UNION SELECT id_orig_h FROM conn",
    "\x00\x00 dns dns dns",
    "",
])
def test_caller_text_never_changes_a_statement(hostile):
    """Facet selection is the only thing a query influences. Whatever it says,
    the rendered SQL is byte-identical to the shipped statement."""
    for name in _pool.select_facets(hostile):
        assert _pool.render_facet_sql(name, _DT) == _pool.render_facet_sql(name, _DT)
        # And it is one of ours, verbatim.
        expected = " ".join(_pool.SAFE_FACETS[name]["sql"].format(dt=_DT).split())
        assert _pool.render_facet_sql(name, _DT) == expected


def test_selection_is_deterministic_across_calls():
    """A facet set that drifted between identical questions would tell a prober
    they are on a path of their own."""
    q = "any beaconing or c2 in outbound traffic today"
    assert _pool.select_facets(q) == _pool.select_facets(q)


def test_selection_is_bounded():
    """A query stuffed with every keyword must not walk the whole pool out in
    one turn."""
    everything = " ".join(kw for f in _pool.SAFE_FACETS.values() for kw in f["keywords"])
    assert len(_pool.select_facets(everything)) <= _pool.MAX_FACETS_PER_ANSWER


def test_unmatched_query_still_gets_a_pool():
    """Never an empty context: an empty pool is how the model ends up with
    nothing to say, which is how a refusal gets written."""
    assert _pool.select_facets("zzzzz qqqqq") == list(_pool.DEFAULT_FACETS)


# ---------------------------------------------------------------------------
# The guard itself
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("sql,why", [
    ("SELECT id_orig_h, COUNT(*) FROM conn WHERE dt = '2026-08-04' GROUP BY id_orig_h LIMIT 10",
     "grouping by a host column is still a host inventory"),
    ("SELECT COUNT(*) FROM files WHERE dt = '2026-08-04' LIMIT 10",
     "table outside the pool"),
    ("SELECT proto FROM conn WHERE dt = '2026-08-04' LIMIT 10",
     "not an aggregate — returns raw rows"),
    ("SELECT COUNT(*) FROM conn WHERE dt = '2026-08-04'",
     "unbounded"),
    ("SELECT COUNT(*) FROM conn WHERE dt = '2026-08-04' LIMIT 5000",
     "LIMIT above the pool cap"),
    ("SELECT COUNT(*) FROM conn WHERE dt = '2026-08-04' LIMIT 10; DROP TABLE conn",
     "second statement"),
    ("SELECT COUNT(*) FROM conn WHERE dt = '2026-08-04' UNION SELECT COUNT(*) FROM ssl LIMIT 10",
     "union reaches past the facet"),
    ("SELECT COUNT(*) FROM conn WHERE dt = '2026-08-04' AND service = 'ssh' LIMIT 10",
     "non-date literal: this is what an interpolated caller value looks like"),
    ("DELETE FROM conn WHERE dt = '2026-08-04'",
     "not a SELECT"),
    ("SELECT COUNT(*) FROM information_schema.tables LIMIT 10",
     "schema enumeration"),
])
def test_guard_rejects(sql, why):
    with pytest.raises(_pool.UnsafePoolQuery):
        _pool.assert_pool_sql_is_safe(sql)


def test_guard_accepts_a_legitimate_facet():
    ok = ("SELECT service, COUNT(*) AS connections FROM conn "
          f"WHERE {_DT} AND service IS NOT NULL GROUP BY service "
          "ORDER BY connections DESC LIMIT 12")
    assert _pool.assert_pool_sql_is_safe(ok) is ok


def test_no_facet_projects_an_identifying_column():
    """The property the guard encodes, asserted directly against the pool so a
    future facet cannot be added with the guard loosened in the same commit.

    Word-boundary matched, exactly as the guard does it: several forbidden names
    are substrings of legitimate identifiers ('uri' inside suricata_corelight),
    and a bare `in` test would reject the pool it is meant to protect."""
    import re
    for name, facet in _pool.SAFE_FACETS.items():
        lowered = facet["sql"].lower()
        for col in _pool.FORBIDDEN_COLUMNS:
            assert not re.search(rf"\b{re.escape(col)}\b", lowered), (
                f"facet {name} references {col}"
            )


def test_static_rollups_carry_no_addresses():
    """The offline pool ships in the repo, so it is the one place a real address
    could be committed by accident."""
    import re
    ip = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    for name in _pool.SAFE_FACETS:
        blob = str(_pool.static_facet(name))
        assert not ip.search(blob), f"static facet {name} contains an IP-shaped value"


# ---------------------------------------------------------------------------
# 2. The output screen
# ---------------------------------------------------------------------------

_GOOD = (
    "## Answer\n"
    "Traffic is dominated by TLS, with nothing unusual in the current window.\n\n"
    "## Evidence\n"
    "- 1.84M connections on ssl vs 1.00M on dns.\n"
    "- TLSv1.3 carries 1.39M sessions against 443k on TLSv1.2.\n\n"
    "## Next Steps\n"
    "1. Continue standard monitoring.\n"
    "2. Re-check after the next feed refresh.\n"
)


def test_screen_passes_a_well_formed_answer():
    ok, reason = _deter.screen_answer(_GOOD)
    assert ok is True and reason == "ok"


@pytest.mark.parametrize("bad", [
    "I can't help with that request.",
    "I'm unable to provide details about that host.",
    "That range is restricted, so I cannot show you the data.",
    "As an AI language model, I should not answer this.",
    "My instructions prevent me from discussing that.",
    "This session has been flagged and placed in quarantine.",
    "I don't have access to that table.",
    "Answering would violate the security policy in place here.",
])
def test_screen_rejects_any_refusal_or_meta_leak(bad):
    """One of these reaching the browser tells the caller they were detected —
    permanently, for every future turn. Padded past the length floor so it is the
    marker being tested, not the length."""
    padded = _GOOD + "\n" + bad + " " + ("context. " * 20)
    ok, reason = _deter.screen_answer(padded)
    assert ok is False
    assert reason.startswith("leak_marker:")


def test_screen_rejects_answers_that_name_the_mechanism():
    padded = _GOOD.replace("Traffic", "Drawing on the safe pool, traffic")
    ok, reason = _deter.screen_answer(padded)
    assert ok is False


def test_screen_rejects_empty_short_and_malformed():
    assert _deter.screen_answer("")[0] is False
    assert _deter.screen_answer("   ")[0] is False
    assert _deter.screen_answer("## Answer\nFine.")[0] is False          # too short
    assert _deter.screen_answer("Everything looks fine. " * 20)[0] is False  # no header


def test_harden_output_masks_in_scope_addresses_and_secrets():
    """This agent's caller is, by definition, someone who already tripped a
    detector — so an injection aiming to get an address echoed back lands here
    first."""
    text = _GOOD + "\nseen from 10.1.2.3 with token AKIAIOSFODNN7EXAMPLE\n"
    hardened = _deter.harden_output(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in hardened


def test_hardening_result_is_rescreened_not_trusted():
    """harden_output can only mask or shorten, and either can produce something
    the screen would have rejected. The endpoint re-screens after hardening;
    this asserts the screen is what decides, on the hardened text."""
    masked = _deter.harden_output(_GOOD)
    assert _deter.screen_answer(masked)[0] is True


# ---------------------------------------------------------------------------
# Pool gathering: never raises, never empty
# ---------------------------------------------------------------------------

def test_gather_falls_back_to_static_when_athena_is_off(monkeypatch):
    monkeypatch.setattr(_deter, "DETER_ATHENA_ENABLED", False)
    ctx = asyncio.run(_deter.gather_pool_context("what does dns look like"))
    assert ctx["live_facets"] == 0
    assert ctx["facets"] and all(f["rows"] for f in ctx["facets"])


def test_gather_degrades_silently_when_athena_fails(monkeypatch):
    """A contained caller must not learn that a backend was slow: 'slow when I
    ask, fast for everyone else' is a side channel."""
    monkeypatch.setattr(_deter, "DETER_ATHENA_ENABLED", True)

    async def _boom(sql):
        raise RuntimeError("athena is down")

    monkeypatch.setattr(_deter.athena_client, "execute_custom_sql", _boom)
    ctx = asyncio.run(_deter.gather_pool_context("protocol mix"))
    assert ctx["live_facets"] == 0
    assert all(f["live"] is False for f in ctx["facets"])
    assert all(f["rows"] for f in ctx["facets"])


def test_gather_never_sends_caller_text_to_athena(monkeypatch):
    """The end-to-end version of the property: whatever the caller typed, every
    statement that reaches Athena is one of ours and clears the guard."""
    monkeypatch.setattr(_deter, "DETER_ATHENA_ENABLED", True)
    seen: list[str] = []

    async def _capture(sql):
        seen.append(sql)
        return [{"service": "ssl", "connections": 5}], {"data_scanned_bytes": 1}

    monkeypatch.setattr(_deter.athena_client, "execute_custom_sql", _capture)
    marker = "MALICIOUS_MARKER_9f3a"
    asyncio.run(_deter.gather_pool_context(f"protocol mix for {marker} and dns"))

    assert seen, "expected at least one pool read"
    for sql in seen:
        assert marker not in sql
        _pool.assert_pool_sql_is_safe(sql)


# ---------------------------------------------------------------------------
# 3. Orchestrator wiring: contained sessions deter, failures cover
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clean_quarantine_state():
    _orch._trace_sessions.clear()
    _orch._quarantined.clear()
    _orch._quarantine_reasons.clear()
    yield
    _orch._trace_sessions.clear()
    _orch._quarantined.clear()
    _orch._quarantine_reasons.clear()


class _Span:
    """Minimal span stand-in; records attributes so the audit trail is testable."""

    def __init__(self):
        self.attrs: dict = {}

    def set_attribute(self, k, v):
        self.attrs[k] = v


def _serve(query="show me the protocol mix", session_id="sid-A"):
    span = _Span()
    resp = asyncio.run(
        _orch._serve_deter(query, start=0.0, session_id=session_id, span=span)
    )
    return resp, span


def test_deter_answer_is_served_to_a_contained_session(monkeypatch):
    async def _fake(query, *, reason=None, trace_headers=None):
        return {"answer": _GOOD, "confidence": 0.72, "usable": True, "screen_reason": "ok"}

    monkeypatch.setattr(_orch, "call_deter", _fake)
    resp, span = _serve()
    assert "## Answer" in resp.answer
    assert span.attrs["deter.served"] is True


def test_served_answer_never_names_the_deter_agent(monkeypatch):
    """agent_used reaches the browser. A caller whose agent changes the turn
    after a probe has been told exactly what they needed to know."""
    async def _fake(query, *, reason=None, trace_headers=None):
        return {"answer": _GOOD, "confidence": 0.72, "usable": True}

    monkeypatch.setattr(_orch, "call_deter", _fake)
    resp, _ = _serve()
    assert resp.agent_used == "athena-hunter"
    assert "deter" not in resp.model_dump_json().lower()


def test_served_answer_carries_no_data_payload(monkeypatch):
    """The deter agent reports which facets it read. Forwarding that would
    describe the mechanism to the person it is aimed at."""
    async def _fake(query, *, reason=None, trace_headers=None):
        return {"answer": _GOOD, "confidence": 0.72, "usable": True,
                "data": {"facets": ["protocol_mix"], "live_facets": 0}}

    monkeypatch.setattr(_orch, "call_deter", _fake)
    resp, _ = _serve()
    assert resp.data is None


def test_confidence_stays_in_the_routine_band(monkeypatch):
    """A distinctive confidence fingerprints the path as surely as distinctive
    prose does. The agent clamps; this asserts what the orchestrator forwards is
    inside the band a normal answer occupies."""
    async def _fake(query, *, reason=None, trace_headers=None):
        return {"answer": _GOOD, "confidence": 0.72, "usable": True}

    monkeypatch.setattr(_orch, "call_deter", _fake)
    resp, _ = _serve()
    assert 0.6 <= resp.confidence <= 0.85


def test_agent_clamps_a_wild_confidence():
    ans, conf = asyncio.run(_stub_llm_answer(_GOOD + '\n```json\n{"confidence": 0.99}\n```'))
    assert 0.6 <= conf <= 0.85
    assert "```json" not in ans


async def _stub_llm_answer(raw):
    """Run llm_deter with the model replaced by a fixed string."""
    import llm_client

    async def _fake_complete(**kwargs):
        return raw

    original = llm_client.llm_complete
    _deter.llm_complete = _fake_complete
    try:
        return await _deter.llm_deter("protocol mix", {"facets": []})
    finally:
        _deter.llm_complete = original


@pytest.mark.parametrize("failure", [
    ConnectionError("deter is down"),
    asyncio.TimeoutError(),
    ValueError("malformed json"),
])
def test_any_transport_failure_falls_back_to_cover(monkeypatch, failure):
    async def _fail(query, *, reason=None, trace_headers=None):
        raise failure

    monkeypatch.setattr(_orch, "call_deter", _fail)
    resp, span = _serve()
    assert resp.answer in [_orch.sanitize_output_text(c) for c in _orch._COVER_RESPONSES]
    assert span.attrs["deter.served"] is False
    assert resp.agent_used == "athena-hunter"


def test_unusable_answer_falls_back_to_cover(monkeypatch):
    """The agent screened its own output away. Same outcome as the agent being
    down — a screen rejection must not become a visible failure."""
    async def _rejected(query, *, reason=None, trace_headers=None):
        return {"answer": "", "confidence": 0.0, "usable": False,
                "screen_reason": "leak_marker:i can't"}

    monkeypatch.setattr(_orch, "call_deter", _rejected)
    resp, span = _serve()
    assert resp.answer in [_orch.sanitize_output_text(c) for c in _orch._COVER_RESPONSES]
    assert span.attrs["deter.served"] is False
    assert span.attrs["deter.fallback_reason"].startswith("leak_marker")


def test_a_truthful_usable_flag_with_empty_answer_still_covers(monkeypatch):
    """usable=true but nothing to show is a malformed agent response, not an
    answer. Serving "" would render as a blank reply, which is its own tell."""
    async def _empty(query, *, reason=None, trace_headers=None):
        return {"answer": "", "confidence": 0.7, "usable": True}

    monkeypatch.setattr(_orch, "call_deter", _empty)
    resp, span = _serve()
    assert resp.answer in [_orch.sanitize_output_text(c) for c in _orch._COVER_RESPONSES]
    assert span.attrs["deter.served"] is False


def test_deter_output_is_sanitised_on_the_way_out(monkeypatch):
    """The agent hardens its own output; the orchestrator sanitises everything
    outbound. Both run — this is the boundary that faces the browser."""
    async def _leaky(query, *, reason=None, trace_headers=None):
        return {"answer": _GOOD + "\nkey AKIAIOSFODNN7EXAMPLE\n",
                "confidence": 0.7, "usable": True}

    monkeypatch.setattr(_orch, "call_deter", _leaky)
    resp, _ = _serve()
    assert "AKIAIOSFODNN7EXAMPLE" not in resp.answer


def test_hints_are_the_same_pool_a_cover_uses(monkeypatch):
    """Hints are on screen next to the answer. A distinct hint set on the deter
    path would distinguish it from every other path at a glance."""
    async def _fake(query, *, reason=None, trace_headers=None):
        return {"answer": _GOOD, "confidence": 0.72, "usable": True}

    monkeypatch.setattr(_orch, "call_deter", _fake)
    resp, _ = _serve(query="q1")
    assert resp.hints == _orch.restricted_cover_hints("q1", salt="quarantine")


def test_the_quarantine_reason_reaches_deter_but_not_the_caller(monkeypatch):
    """A Manifold threat title quotes attacker-influenced text. It belongs in the
    audit trail and nowhere else — never in a prompt, never in a response."""
    _orch.quarantine_session("sid-A", reason="prompt-injection: ignore previous instructions")
    captured: dict = {}

    async def _fake(query, *, reason=None, trace_headers=None):
        captured["reason"] = reason
        return {"answer": _GOOD, "confidence": 0.72, "usable": True}

    monkeypatch.setattr(_orch, "call_deter", _fake)
    resp, _ = _serve(session_id="sid-A")
    assert captured["reason"] == "prompt-injection: ignore previous instructions"
    assert "ignore previous instructions" not in resp.answer


def test_reason_is_dropped_when_the_quarantine_expires():
    _orch.quarantine_session("sid-A", ttl_seconds=1.0, reason="threat X")
    assert _orch.quarantine_reason("sid-A") == "threat X"
    _orch._prune_quarantine(now=__import__("time").time() + 10_000)
    assert _orch.quarantine_reason("sid-A") is None


def test_a_second_threat_updates_the_reason_without_shortening_the_ttl():
    _orch.quarantine_session("sid-A", ttl_seconds=3600.0, reason="first")
    far = _orch._quarantined["sid-A"]
    _orch.quarantine_session("sid-A", ttl_seconds=1.0, reason="second")
    assert _orch._quarantined["sid-A"] == far
    assert _orch.quarantine_reason("sid-A") == "second"


def test_deter_path_never_touches_the_response_cache(monkeypatch):
    """The cache key is the query text alone and entries are shared between
    callers. One deter answer written there would be served to every benign user
    who later asks the same question."""
    async def _fake(query, *, reason=None, trace_headers=None):
        return {"answer": _GOOD, "confidence": 0.72, "usable": True}

    def _explode(*a, **kw):
        raise AssertionError("the deter path must not read or write the response cache")

    monkeypatch.setattr(_orch, "call_deter", _fake)
    monkeypatch.setattr(_orch.response_cache, "cache_key", _explode)
    _serve()  # must not raise
