"""Lane mode: the runtime cloud / local / hybrid switch behind the settings gear.

The env is the boot default and the override is process state. Most of what matters
here is about the boundaries between those two, plus one property that is a security
statement rather than a convenience: local-only must never silently serve the cloud.
Somebody selects local-only because they do not want conference query text leaving the
box, and a quiet fallback to Gemini would be the worst possible failure of that
control.
"""

from __future__ import annotations

import asyncio
import importlib

import pytest

import llm_client


@pytest.fixture(autouse=True)
def _clean_mode():
    """No test may leak an override into the next one; the state is module-global."""
    llm_client.reset_lane_mode()
    yield
    llm_client.reset_lane_mode()


def _no_local(monkeypatch):
    for var in ("LOCAL_SQL_BASE_URL", "LOCAL_PROSE_BASE_URL", "LOCAL_LLM_BASE_URL"):
        monkeypatch.delenv(var, raising=False)


def _with_local(monkeypatch):
    monkeypatch.setenv("LOCAL_SQL_BASE_URL", "http://gpu:8080/v1")


class TestEnvDefault:
    def test_a_cpu_box_defaults_to_cloud_only(self, monkeypatch):
        """No local endpoint means no local lane, and no dead calls to prove it."""
        _no_local(monkeypatch)
        monkeypatch.delenv("LANE_MODE", raising=False)
        monkeypatch.setattr(llm_client, "LANE_RACE", "auto")
        assert llm_client.lane_mode() == llm_client.MODE_CLOUD
        assert llm_client.lane_race_enabled() is False

    def test_a_gpu_box_defaults_to_hybrid(self, monkeypatch):
        _with_local(monkeypatch)
        monkeypatch.delenv("LANE_MODE", raising=False)
        monkeypatch.setattr(llm_client, "LANE_RACE", "auto")
        assert llm_client.lane_mode() == llm_client.MODE_HYBRID
        assert llm_client.lane_race_enabled() is True

    def test_lane_race_off_still_means_cloud_only(self, monkeypatch):
        """Back-compat: "off" already meant one pipeline, and the cloud answered it."""
        _with_local(monkeypatch)
        monkeypatch.delenv("LANE_MODE", raising=False)
        monkeypatch.setattr(llm_client, "LANE_RACE", "off")
        assert llm_client.lane_mode() == llm_client.MODE_CLOUD
        assert llm_client.lane_race_enabled() is False

    def test_lane_race_on_races_even_unconfigured(self, monkeypatch):
        """An operator override that lets a misconfigured box fail loudly."""
        _no_local(monkeypatch)
        monkeypatch.delenv("LANE_MODE", raising=False)
        monkeypatch.setattr(llm_client, "LANE_RACE", "on")
        assert llm_client.lane_mode() == llm_client.MODE_HYBRID
        assert llm_client.lane_race_enabled() is True

    def test_lane_mode_env_beats_lane_race(self, monkeypatch):
        _with_local(monkeypatch)
        monkeypatch.setenv("LANE_MODE", "local")
        monkeypatch.setattr(llm_client, "LANE_RACE", "on")
        assert llm_client.lane_mode() == llm_client.MODE_LOCAL
        assert llm_client.lane_race_enabled() is False

    def test_a_nonsense_lane_mode_is_ignored(self, monkeypatch):
        """A typo in the env must not brick the box; fall through to LANE_RACE."""
        _with_local(monkeypatch)
        monkeypatch.setenv("LANE_MODE", "hybird")
        monkeypatch.setattr(llm_client, "LANE_RACE", "auto")
        assert llm_client.lane_mode() == llm_client.MODE_HYBRID


class TestRuntimeOverride:
    def test_an_override_beats_the_env(self, monkeypatch):
        _with_local(monkeypatch)
        monkeypatch.setattr(llm_client, "LANE_RACE", "auto")
        assert llm_client.lane_mode() == llm_client.MODE_HYBRID
        llm_client.set_lane_mode("local")
        assert llm_client.lane_mode() == llm_client.MODE_LOCAL
        assert llm_client.lane_race_enabled() is False

    def test_reset_falls_back_to_the_env(self, monkeypatch):
        _with_local(monkeypatch)
        monkeypatch.setattr(llm_client, "LANE_RACE", "auto")
        llm_client.set_lane_mode("cloud")
        assert llm_client.lane_mode() == llm_client.MODE_CLOUD
        llm_client.set_lane_mode(None)
        assert llm_client.lane_mode() == llm_client.MODE_HYBRID

    def test_an_unknown_mode_is_refused(self):
        with pytest.raises(ValueError):
            llm_client.set_lane_mode("gpu-go-brrr")

    def test_a_refused_mode_does_not_change_anything(self, monkeypatch):
        _with_local(monkeypatch)
        monkeypatch.setattr(llm_client, "LANE_RACE", "auto")
        llm_client.set_lane_mode("cloud")
        with pytest.raises(ValueError):
            llm_client.set_lane_mode("nonsense")
        assert llm_client.lane_mode() == llm_client.MODE_CLOUD

    def test_set_returns_the_state_it_just_set(self, monkeypatch):
        """So a caller never has to re-read and risk reporting something else."""
        _with_local(monkeypatch)
        state = llm_client.set_lane_mode("local", side_by_side=False)
        assert state["mode"] == "local"
        assert state["side_by_side"] is False
        assert state["overridden"] is True

    def test_the_override_does_not_persist_across_a_reload(self, monkeypatch):
        """Process state on purpose: a 2am demo setting must not outlive the container."""
        _with_local(monkeypatch)
        llm_client.set_lane_mode("local")
        reloaded = importlib.reload(llm_client)
        try:
            assert reloaded.lane_mode() != reloaded.MODE_LOCAL or \
                   reloaded._lane_mode is None
            assert reloaded._lane_mode is None
        finally:
            importlib.reload(llm_client)


class TestLocalOnlyNeverFallsBackToCloud:
    """The one property here that is a security statement, not a convenience."""

    def test_local_only_is_honoured_with_no_local_endpoint(self, monkeypatch):
        """It fails loudly rather than quietly shipping the query to Gemini.

        Someone picks local-only because the query text must not leave the box. A
        silent fallback would defeat exactly that, at the moment nobody is watching.
        """
        _no_local(monkeypatch)
        llm_client.set_lane_mode("local")
        assert llm_client.lane_mode() == llm_client.MODE_LOCAL
        assert llm_client.single_lane() == llm_client.LANE_LOCAL
        assert llm_client.lane_race_enabled() is False

    def test_state_flags_a_mode_that_cannot_answer(self, monkeypatch):
        """The UI has to be able to warn, rather than leaving it to failed queries."""
        _no_local(monkeypatch)
        llm_client.set_lane_mode("local")
        state = llm_client.lane_mode_state()
        assert state["local_configured"] is False
        assert state["local_missing"] is True

    def test_cloud_only_is_not_flagged_as_missing_local(self, monkeypatch):
        _no_local(monkeypatch)
        llm_client.set_lane_mode("cloud")
        assert llm_client.lane_mode_state()["local_missing"] is False


class TestSingleLanePinning:
    def test_an_explicit_mode_pins_the_lane(self, monkeypatch):
        _with_local(monkeypatch)
        llm_client.set_lane_mode("cloud")
        assert llm_client.single_lane() == llm_client.LANE_CLOUD
        llm_client.set_lane_mode("local")
        assert llm_client.single_lane() == llm_client.LANE_LOCAL

    def test_hybrid_pins_nothing(self, monkeypatch):
        _with_local(monkeypatch)
        llm_client.set_lane_mode("hybrid")
        assert llm_client.single_lane() is None

    def test_an_inherited_mode_does_not_pin(self, monkeypatch):
        """LANE_RACE=off must keep meaning "use LLM_PROVIDER".

        Pinning it to the cloud lane would silently switch a box running
        LLM_PROVIDER=openrouter over to Gemini, which nobody asked for.
        """
        _no_local(monkeypatch)
        monkeypatch.delenv("LANE_MODE", raising=False)
        monkeypatch.setattr(llm_client, "LANE_RACE", "off")
        assert llm_client.lane_mode() == llm_client.MODE_CLOUD
        assert llm_client.single_lane() is None

    def test_lane_mode_in_the_env_does_pin(self, monkeypatch):
        """Setting it explicitly is a different statement from inheriting it."""
        _no_local(monkeypatch)
        monkeypatch.setenv("LANE_MODE", "cloud")
        assert llm_client.single_lane() == llm_client.LANE_CLOUD


class TestSideBySide:
    def test_on_by_default(self, monkeypatch):
        monkeypatch.delenv("LANE_SIDE_BY_SIDE", raising=False)
        assert llm_client.side_by_side_enabled() is True

    @pytest.mark.parametrize("val", ["false", "0", "no", "off", "OFF"])
    def test_env_can_turn_it_off(self, monkeypatch, val):
        monkeypatch.setenv("LANE_SIDE_BY_SIDE", val)
        assert llm_client.side_by_side_enabled() is False

    def test_the_override_beats_the_env(self, monkeypatch):
        monkeypatch.setenv("LANE_SIDE_BY_SIDE", "false")
        llm_client.set_lane_mode(None, side_by_side=True)
        assert llm_client.side_by_side_enabled() is True

    def test_changing_mode_alone_leaves_side_by_side_alone(self, monkeypatch):
        """The panel sends both fields, but a caller that sends one must not clear
        the other."""
        _with_local(monkeypatch)
        llm_client.set_lane_mode("hybrid", side_by_side=False)
        llm_client.set_lane_mode("local")
        assert llm_client.side_by_side_enabled() is False

    def test_racing_is_unaffected_by_side_by_side(self, monkeypatch):
        """Off means "do not show the loser", not "do not run the second lane".

        The race is what makes a dead lane free, so it stays on regardless.
        """
        _with_local(monkeypatch)
        llm_client.set_lane_mode("hybrid", side_by_side=False)
        assert llm_client.lane_race_enabled() is True


class TestModeState:
    def test_state_reports_the_env_default_alongside_the_override(self, monkeypatch):
        """So the panel can label one option "deployed default" honestly."""
        _with_local(monkeypatch)
        monkeypatch.delenv("LANE_MODE", raising=False)
        monkeypatch.setattr(llm_client, "LANE_RACE", "auto")
        llm_client.set_lane_mode("cloud")
        state = llm_client.lane_mode_state()
        assert state["mode"] == "cloud"
        assert state["env_mode"] == "hybrid"
        assert state["overridden"] is True

    def test_state_is_not_marked_overridden_when_untouched(self, monkeypatch):
        _with_local(monkeypatch)
        assert llm_client.lane_mode_state()["overridden"] is False

    def test_state_carries_the_role_models_for_the_panel(self, monkeypatch):
        state = llm_client.lane_mode_state()
        assert set(state["roles"]) == {"sqlgen", "prose"}
        for role in state["roles"].values():
            assert "base_url" in role and "model" in role


# ---------------------------------------------------------------------------
# Orchestrator wiring
# ---------------------------------------------------------------------------

from conftest import load_agent_main  # noqa: E402

_orch = load_agent_main("orchestrator", "orch_main_lanemode")


class TestOrchestratorHonoursTheMode:
    def test_single_lane_call_gets_the_pinned_lane(self, monkeypatch):
        """cloud-only has to actually route to the cloud stack, not the ambient one."""
        _with_local(monkeypatch)
        llm_client.set_lane_mode("cloud")
        seen: list[str | None] = []

        async def call(lane):
            seen.append(lane)
            return {"answer": "a", "confidence": 0.7}

        result = asyncio.run(_orch._route_raced("j1", False, "athena-hunter", call,
                                                fallback_confidence=0.5))
        assert seen == [llm_client.LANE_CLOUD]
        assert result["_lane"] == llm_client.LANE_CLOUD

    def test_inherited_single_lane_still_passes_none(self, monkeypatch):
        """The pre-lane behaviour, unchanged: no lane means the ambient provider."""
        _no_local(monkeypatch)
        monkeypatch.delenv("LANE_MODE", raising=False)
        monkeypatch.setattr(llm_client, "LANE_RACE", "off")
        seen: list[str | None] = []

        async def call(lane):
            seen.append(lane)
            return {"answer": "a", "confidence": 0.7}

        result = asyncio.run(_orch._route_raced("j1", False, "athena-hunter", call,
                                                fallback_confidence=0.5))
        assert seen == [None]
        assert "_lane" not in result

    def test_side_by_side_off_cancels_the_loser(self, monkeypatch):
        """Nobody will read it, so do not pay for a second Athena scan to store it."""
        _with_local(monkeypatch)
        llm_client.set_lane_mode("hybrid", side_by_side=False)
        finished: list[str] = []

        async def call(lane):
            if lane == llm_client.LANE_CLOUD:
                return {"answer": "fast cloud", "confidence": 0.8}
            await asyncio.sleep(5)          # would outlive the test if not cancelled
            finished.append("local")
            return {"answer": "slow local", "confidence": 0.6}

        async def drive():
            result = await _orch._route_raced("j-sbs", True, "athena-hunter", call,
                                              fallback_confidence=0.5)
            # Give a cancelled task a tick to actually unwind.
            await asyncio.sleep(0.05)
            return result

        result = asyncio.run(drive())
        assert result["answer"] == "fast cloud"
        assert finished == [], "the losing lane should have been cancelled"
        assert _orch._lane_store.get("j-sbs") is None, "no store entry to swap to"

    def test_side_by_side_on_keeps_the_loser(self, monkeypatch):
        _with_local(monkeypatch)
        llm_client.set_lane_mode("hybrid", side_by_side=True)

        async def call(lane):
            if lane == llm_client.LANE_CLOUD:
                return {"answer": "fast cloud", "confidence": 0.8}
            await asyncio.sleep(0.02)
            return {"answer": "slow local", "confidence": 0.6}

        async def drive():
            result = await _orch._route_raced("j-keep", True, "athena-hunter", call,
                                              fallback_confidence=0.5)
            await asyncio.sleep(0.2)        # let the drain land
            return result

        result = asyncio.run(drive())
        assert result["answer"] == "fast cloud"
        entry = _orch._lane_store.get("j-keep")
        assert entry is not None
        assert any(l.lane == llm_client.LANE_LOCAL for l in entry.get("lanes", []))

    def test_a_cover_hides_the_swap_when_side_by_side_is_off(self, monkeypatch):
        """A cover has to look like a real answer on the lane surface too.

        If covers offered a swap control while real answers did not, the lane surface
        alone would tell an observer which questions were filtered.
        """
        _with_local(monkeypatch)
        llm_client.set_lane_mode("hybrid", side_by_side=False)
        resp = _orch._serve_cover("anything", start=0.0, salt="quarantine")
        assert resp.lanes == []
        assert resp.lane is None

    def test_a_cover_shows_the_swap_when_side_by_side_is_on(self, monkeypatch):
        _with_local(monkeypatch)
        llm_client.set_lane_mode("hybrid", side_by_side=True)
        resp = _orch._serve_cover("anything", start=0.0, salt="quarantine")
        assert resp.lane is not None
        assert len(resp.lanes) >= 1
