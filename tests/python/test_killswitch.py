"""The admin kill-switch: the plug.

What an operator believes when they throw it: nothing this platform says from
here on was read off the show network. Three things had to be true for that and
only one of them was:

  1. NO SPECIALIST AGENT RUNS. The check used to live inside the athena_hunter
     branch, so a killed platform still answered "any alerts in the last hour?"
     from alert-triage (Athena) and "how's the network?" from
     thousandeyes-analyst (live ThousandEyes API). Only the default branch was
     ever plugged.
  2. NO CACHE HIT IS SERVED. Cached answers were built from live data. Serving
     one after the plug is pulled discloses exactly what pulling it was meant to
     stop, and does it faster than the real thing.
  3. NO LIVE POOL READ. Killed traffic is answered by the deter agent, whose own
     facets can read Athena when DETER_ATHENA_ENABLED is on. "Answer from deter"
     and "no live data" are only compatible if the ban travels on the request.

And the failover, because a kill switch that errors instead of answering
announces that it was thrown: deter down, deter slow, deter disabled, or deter
screening its own answer away all land on the same canned cover every other
guardrail serves.
"""

from __future__ import annotations

import asyncio

import pytest

from conftest import load_agent_main

_orch = load_agent_main("orchestrator", "orch_main")
_deter = load_agent_main("deter", "deter_main")

_GOOD = (
    "## Answer\nConnection volume over the last 24 hours is dominated by TLS, "
    "with DNS second and a long tail of HTTP.\n\n"
    "## Next Steps\n1. Keep watching the protocol mix.\n2. Re-check at the top of the hour.\n"
)


class _Span:
    """Records attributes so the audit trail is testable."""

    def __init__(self):
        self.attrs: dict = {}

    def set_attribute(self, k, v):
        self.attrs[k] = v

    def get_span_context(self):
        return None

    def record_exception(self, exc):
        self.attrs["exception"] = repr(exc)


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    """Switch off, quarantine empty, pacing short enough to test with."""
    _orch._kill_switches["athena_hunter"] = False
    _orch._trace_sessions.clear()
    _orch._quarantined.clear()
    _orch._quarantine_reasons.clear()
    monkeypatch.setattr(_orch, "DETER_PACE_MIN_SECONDS", 0.01)
    monkeypatch.setattr(_orch, "DETER_PACE_MAX_SECONDS", 0.02)
    yield
    _orch._kill_switches["athena_hunter"] = False
    _orch._trace_sessions.clear()
    _orch._quarantined.clear()
    _orch._quarantine_reasons.clear()


def _kill(on: bool = True) -> None:
    _orch._kill_switches["athena_hunter"] = on


def _no_agents(monkeypatch) -> None:
    """Every specialist becomes a tripwire."""
    async def _boom(*a, **kw):
        raise AssertionError("a specialist agent was called with the plug pulled")

    for fn in ("call_athena_hunter", "call_alert_triage", "call_thousandeyes_analyst"):
        monkeypatch.setattr(_orch, fn, _boom)


def _deter_returns(monkeypatch, payload=None, calls: list | None = None):
    async def _fake(query, *, reason=None, trace_headers=None, live_ok=True, **_kw):
        if calls is not None:
            calls.append({"query": query, "reason": reason, "live_ok": live_ok})
        return payload if payload is not None else {
            "answer": _GOOD, "confidence": 0.72, "usable": True, "screen_reason": "ok",
        }

    monkeypatch.setattr(_orch, "call_deter", _fake)


def _ask(query="what is happening on the network right now?", session_id="sid-A"):
    req = _orch.QueryRequest(
        job_id="job-kill-1", query=query,
        client=_orch.ClientInfo(session_id=session_id, ip="10.0.0.9"),
    )
    return asyncio.run(_orch.handle_query(req))


# ---------------------------------------------------------------------------
# 1. Nothing that reads live data runs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("intent", [
    "athena_hunter", "alert_triage", "thousandeyes_analyst", "refused", "threat_hunter",
])
def test_no_specialist_agent_runs_whatever_the_query_would_classify_as(monkeypatch, intent):
    """The hole this closes: alert-triage and thousandeyes-analyst were never
    gated, so two of the four intents kept answering from live data."""
    _no_agents(monkeypatch)
    _deter_returns(monkeypatch)

    async def _classify(query, lane=None):
        return {"intent": intent, "confidence": 0.9, "reasoning": "test"}

    monkeypatch.setattr(_orch, "llm_classify", _classify)
    _kill()

    resp = _ask()
    assert "## Answer" in resp.answer


def test_the_classifier_is_not_even_reached(monkeypatch):
    """Cheapest proof that the check sits in front of routing: with the plug
    pulled there is nothing to classify FOR."""
    _no_agents(monkeypatch)
    _deter_returns(monkeypatch)
    seen: list[str] = []

    async def _classify(query, lane=None):
        seen.append(query)
        return {"intent": "athena_hunter", "confidence": 0.9, "reasoning": "test"}

    monkeypatch.setattr(_orch, "llm_classify", _classify)
    _kill()
    _ask()
    assert seen == [], "the classifier ran with the plug pulled"


def test_the_response_cache_is_never_read_while_killed(monkeypatch):
    """A hit is an answer built from live data, served faster than the real
    thing. Reading the cache here would leak and fingerprint in one move."""
    _no_agents(monkeypatch)
    _deter_returns(monkeypatch)

    async def _boom(key):
        raise AssertionError("the response cache was read with the plug pulled")

    monkeypatch.setattr(_orch, "_cached_answer", _boom)
    _kill()
    resp = _ask()
    assert "## Answer" in resp.answer


def test_the_deter_answer_is_never_written_to_the_cache(monkeypatch):
    _no_agents(monkeypatch)
    _deter_returns(monkeypatch)

    async def _boom(*a, **kw):
        raise AssertionError("a killed-path answer reached the cache")

    monkeypatch.setattr(_orch, "_store_answer", _boom)
    _kill()
    _ask()


# ---------------------------------------------------------------------------
# 2. Deter answers, and is forbidden from reading live data
# ---------------------------------------------------------------------------

def test_killed_traffic_is_answered_by_deter(monkeypatch):
    _no_agents(monkeypatch)
    calls: list = []
    _deter_returns(monkeypatch, calls=calls)
    _kill()

    resp = _ask()
    assert resp.answer.startswith("## Answer")
    assert len(calls) == 1


def test_deter_is_told_it_may_not_read_live_data(monkeypatch):
    """The whole point. DETER_ATHENA_ENABLED is an env var on the box; a pulled
    plug must not depend on how it happens to be set."""
    _no_agents(monkeypatch)
    calls: list = []
    _deter_returns(monkeypatch, calls=calls)
    _kill()
    _ask()
    assert calls[0]["live_ok"] is False


def test_the_kill_path_is_marked_on_the_audit_surface(monkeypatch):
    """Invisible to the caller, obvious to an operator reading the swim lane."""
    _no_agents(monkeypatch)
    _deter_returns(monkeypatch)
    _kill()

    captured: dict = {}
    real = _orch._serve_deter

    async def _spy(query, **kw):
        captured.update(kw)
        return await real(query, **kw)

    monkeypatch.setattr(_orch, "_serve_deter", _spy)
    _ask()
    assert captured["live_ok"] is False
    assert captured["salt"] == "kill_switch"
    assert captured["reason_override"] == "admin kill-switch"


# ---------------------------------------------------------------------------
# 3. Failover: deter is not a single point of failure
# ---------------------------------------------------------------------------

def _covers() -> list[str]:
    return [_orch.sanitize_output_text(c) for c in _orch._COVER_RESPONSES]


@pytest.mark.parametrize("failure", [
    ConnectionError("deter is down"),
    asyncio.TimeoutError(),
    ValueError("malformed json"),
    RuntimeError("deter returned 502"),
])
def test_deter_being_down_falls_back_to_cover(monkeypatch, failure):
    """Deter is still being built. A killed platform whose deter agent is not
    running must still answer — with the canned cover, not an error."""
    _no_agents(monkeypatch)

    async def _fail(query, *, reason=None, trace_headers=None, live_ok=True, **_kw):
        raise failure

    monkeypatch.setattr(_orch, "call_deter", _fail)
    _kill()

    resp = _ask()
    assert resp.answer in _covers()
    assert resp.agent_used == "athena-hunter"


def test_a_screened_away_answer_falls_back_to_cover(monkeypatch):
    _no_agents(monkeypatch)
    _deter_returns(monkeypatch, payload={
        "answer": "", "usable": False, "screen_reason": "leak_marker:i can't",
    })
    _kill()
    assert _ask().answer in _covers()


def test_deter_disabled_falls_back_to_cover(monkeypatch):
    """DETER_ENABLED=false is the deployment state today: the agent is in
    compose but not running on the box."""
    _no_agents(monkeypatch)

    async def _boom(*a, **kw):
        raise AssertionError("call_deter reached while DETER_ENABLED is false")

    monkeypatch.setattr(_orch, "call_deter", _boom)
    monkeypatch.setattr(_orch, "DETER_ENABLED", False)
    _kill()

    resp = _ask()
    assert resp.answer in _covers()


def test_the_fallback_is_the_same_cover_every_other_guardrail_serves(monkeypatch):
    """One copy of the prose. A kill-switch-only variant would be a tell."""
    _no_agents(monkeypatch)

    async def _fail(query, **kw):
        raise ConnectionError("down")

    monkeypatch.setattr(_orch, "call_deter", _fail)
    _kill()
    killed = _ask()

    _kill(False)
    restricted = _orch._serve_cover("anything", start=0.0)
    assert killed.answer in _covers()
    assert restricted.answer in _covers()


# ---------------------------------------------------------------------------
# 4. The caller cannot tell
# ---------------------------------------------------------------------------

def test_the_response_never_names_the_mechanism(monkeypatch):
    _no_agents(monkeypatch)
    _deter_returns(monkeypatch)
    _kill()

    body = _ask().model_dump_json().lower()
    for word in ("deter", "kill", "switch", "quarantin", "cover", "disabled"):
        assert word not in body, f"response leaks {word!r}"


def test_agent_used_does_not_change_when_the_plug_is_pulled(monkeypatch):
    """A caller whose reported agent changes the turn after the switch is thrown
    has been told the switch was thrown."""
    _no_agents(monkeypatch)
    _deter_returns(monkeypatch)
    _kill()
    assert _ask().agent_used == "athena-hunter"


def test_hints_are_still_offered(monkeypatch):
    """An answer that suddenly stops offering follow-ups is as distinguishable
    as one that changes its prose."""
    _no_agents(monkeypatch)
    _deter_returns(monkeypatch)
    _kill()
    assert _ask().hints


# ---------------------------------------------------------------------------
# 5. Restore
# ---------------------------------------------------------------------------

def test_restoring_the_switch_resumes_normal_routing(monkeypatch):
    """The switch has to be reversible or nobody will throw it."""
    seen: list[str] = []

    async def _athena(query, iocs, trace_headers=None, lane=None):
        seen.append(query)
        return {"answer": "## Answer\nreal athena answer", "confidence": 0.8, "data": None}

    async def _classify(query, lane=None):
        return {"intent": "athena_hunter", "confidence": 0.9, "reasoning": "test"}

    async def _no_hit(key):
        return None

    async def _no_store(*a, **kw):
        return None

    monkeypatch.setattr(_orch, "call_athena_hunter", _athena)
    monkeypatch.setattr(_orch, "llm_classify", _classify)
    monkeypatch.setattr(_orch, "lane_race_enabled", lambda: False)
    monkeypatch.setattr(_orch, "_cached_answer", _no_hit)
    monkeypatch.setattr(_orch, "_store_answer", _no_store)

    _kill(True)
    _deter_returns(monkeypatch)
    assert seen == []

    _kill(False)
    resp = _ask()
    assert seen, "athena-hunter never ran after the switch was restored"
    assert "real athena answer" in resp.answer


def test_live_data_killed_reads_the_switch_the_admin_route_writes():
    """One flag, two names would be the whole bug: the audit monitor's button
    and the web-server's feed freeze both post/read `athena_hunter`."""
    _orch._kill_switches["athena_hunter"] = True
    assert _orch.live_data_killed() is True
    _orch._kill_switches["athena_hunter"] = False
    assert _orch.live_data_killed() is False


# ---------------------------------------------------------------------------
# 6. The deter agent honours the ban
#
# test_deter.py section 5 owns the agent-side half of this (it obeys live_ok
# even with DETER_ATHENA_ENABLED on, and a killed answer still carries content).
# What is left here is the shape of the flag itself.
# ---------------------------------------------------------------------------

def test_the_ban_can_only_subtract(monkeypatch):
    """live_ok is a veto, not a second way to switch live reads on."""
    monkeypatch.setattr(_deter, "DETER_ATHENA_ENABLED", False)

    async def _boom(sql):
        raise AssertionError("deter read Athena with DETER_ATHENA_ENABLED off")

    monkeypatch.setattr(_deter.athena_client, "execute_custom_sql", _boom)
    ctx = asyncio.run(_deter.gather_pool_context("protocol mix", live_ok=True))
    assert ctx["live_facets"] == 0


def test_live_reads_still_happen_when_allowed_and_enabled(monkeypatch):
    monkeypatch.setattr(_deter, "DETER_ATHENA_ENABLED", True)

    async def _rows(sql):
        return [{"service": "ssl", "connections": 5}], {"data_scanned_bytes": 1}

    monkeypatch.setattr(_deter.athena_client, "execute_custom_sql", _rows)
    ctx = asyncio.run(_deter.gather_pool_context("protocol mix", live_ok=True))
    assert ctx["live_facets"] > 0


def test_the_request_defaults_to_allowing_live_reads():
    """Back-compat: an older orchestrator that doesn't send the field must not
    accidentally put the agent into static mode."""
    assert _deter.DeterRequest(query="anything").live_ok is True
    assert _deter.DeterRequest(query="anything", live_ok=False).live_ok is False


# ---------------------------------------------------------------------------
# 7. Placement, asserted structurally (same style as the cache tests)
# ---------------------------------------------------------------------------

def test_the_kill_check_precedes_classification_and_every_cache_lookup():
    import inspect
    src = inspect.getsource(_orch.handle_query)
    kill = src.index("live_data_killed()")
    assert kill < src.index("_route_cached")
    assert kill < src.index("llm_classify")
    assert kill < src.index("_classify_raced")


def test_no_second_kill_check_survives_inside_a_branch():
    """The athena-branch check is gone. Leaving it would be harmless today and
    misleading tomorrow — it reads as if that branch is the one being guarded."""
    import inspect
    src = inspect.getsource(_orch.handle_query)
    assert src.count("live_data_killed()") == 1
    assert "_kill_switches.get(" not in src


# ---------------------------------------------------------------------------
# 8. The button itself: through the HTTP routes, not the module global
# ---------------------------------------------------------------------------

class TestTheButtonEndToEnd:
    """The audit monitor's control is `POST /admin/killswitch/athena` followed by
    ordinary `POST /query` traffic. Everything above pokes the flag directly;
    this drives the same wire path an operator does, so an auth or wiring
    regression cannot hide behind a green unit test."""

    TOKEN = "test-admin-token"

    @pytest.fixture
    def client(self, monkeypatch):
        from fastapi.testclient import TestClient
        monkeypatch.setattr(_orch, "ADMIN_BEARER_TOKEN", self.TOKEN)
        return TestClient(_orch.app)

    def _auth(self):
        return {"Authorization": f"Bearer {self.TOKEN}"}

    def test_the_switch_cannot_be_thrown_without_the_admin_bearer(self, client):
        """It is reachable from the admin UI's origin, so a session cookie alone
        must not be enough to pull the plug — or to put it back."""
        for headers in ({}, {"Authorization": "Bearer wrong-token"}):
            r = client.post("/admin/killswitch/athena", json={"killed": True}, headers=headers)
            assert r.status_code == 401
        assert _orch.live_data_killed() is False

    def test_the_button_cuts_live_data_and_the_answer_still_arrives(self, client, monkeypatch):
        _no_agents(monkeypatch)
        _deter_returns(monkeypatch)

        r = client.post("/admin/killswitch/athena", json={"killed": True}, headers=self._auth())
        assert r.status_code == 200 and r.json()["athena_hunter"] is True
        assert client.get("/admin/killswitch", headers=self._auth()).json()["athena_hunter"] is True

        q = client.post("/query", json={"job_id": "job-e2e", "query": "any alerts in the last hour?"})
        assert q.status_code == 200
        body = q.json()
        assert body["answer"].startswith("## Answer")
        assert body["agent_used"] == "athena-hunter"

    def test_with_deter_down_the_button_still_answers(self, client, monkeypatch):
        """The state the platform is in today: deter is built but not deployed."""
        _no_agents(monkeypatch)

        async def _down(query, **kw):
            raise ConnectionError("no deter container on this box")

        monkeypatch.setattr(_orch, "call_deter", _down)
        client.post("/admin/killswitch/athena", json={"killed": True}, headers=self._auth())

        body = client.post(
            "/query", json={"job_id": "job-e2e-2", "query": "how is the network quality?"},
        ).json()
        assert body["answer"] in _covers()

    def test_the_button_restores(self, client, monkeypatch):
        _deter_returns(monkeypatch)
        client.post("/admin/killswitch/athena", json={"killed": True}, headers=self._auth())
        r = client.post("/admin/killswitch/athena", json={"killed": False}, headers=self._auth())
        assert r.json()["athena_hunter"] is False
        assert _orch.live_data_killed() is False
