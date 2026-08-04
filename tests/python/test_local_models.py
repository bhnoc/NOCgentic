"""Local model discovery and control (agents/shared/local_models.py).

The security-relevant assertions are the ones about what can cross the boundary to
the host supervisor. The orchestrator may name an allowlist KEY and nothing else: no
paths, no flags, no command strings. Everything else here is about failing usefully,
because a settings panel that cannot explain why a control is unavailable is worse
than one that does not offer it.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

import llm_client
import local_models


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("boom", request=None, response=None)  # type: ignore[arg-type]


class FakeClient:
    """Stand-in for httpx.AsyncClient. Records requests, returns scripted responses."""

    def __init__(self, routes: dict[str, FakeResponse] | None = None, raise_on=None):
        self.routes = routes or {}
        self.raise_on = raise_on or set()
        self.gets: list[str] = []
        self.posts: list[tuple[str, dict]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def _lookup(self, url: str) -> FakeResponse:
        for frag, resp in self.routes.items():
            if frag in url:
                return resp
        return FakeResponse(404, {"detail": "no route"})

    async def get(self, url, **kw):
        self.gets.append(url)
        if any(f in url for f in self.raise_on):
            raise httpx.ConnectError("refused")
        return self._lookup(url)

    async def post(self, url, json=None, **kw):
        self.posts.append((url, json or {}))
        if any(f in url for f in self.raise_on):
            raise httpx.ConnectError("refused")
        return self._lookup(url)


@pytest.fixture
def client_factory(monkeypatch):
    """Install a FakeClient and hand the test a handle on it."""
    holder: dict[str, FakeClient] = {}

    def install(client: FakeClient) -> FakeClient:
        holder["c"] = client
        monkeypatch.setattr(local_models.httpx, "AsyncClient", lambda **kw: client)
        return client

    return install


class TestDiscovery:
    def test_reports_what_each_endpoint_is_serving(self, client_factory, monkeypatch):
        monkeypatch.setattr(llm_client, "LOCAL_SQL_BASE_URL", "http://gpu:8080/v1")
        monkeypatch.setattr(llm_client, "LOCAL_PROSE_BASE_URL", "http://gpu:8080/v1")
        monkeypatch.setattr(llm_client, "LOCAL_SQL_MODEL", "AQLight")
        monkeypatch.setattr(llm_client, "LOCAL_PROSE_MODEL", "AQLight")
        monkeypatch.setattr(local_models, "SUPERVISOR_URL", "")
        client_factory(FakeClient({"/models": FakeResponse(
            200, {"data": [{"id": "AQLight"}]})}))

        inv = asyncio.run(local_models.inventory())

        assert inv["roles"]["sqlgen"]["serving"] == ["AQLight"]
        assert inv["roles"]["sqlgen"]["reachable"] is True
        assert inv["roles"]["sqlgen"]["healthy"] is True

    def test_flags_a_server_serving_the_wrong_model(self, client_factory, monkeypatch):
        """The silent misconfiguration this panel exists to surface.

        The endpoint answers, so nothing looks broken, but the lane asks for a model
        alias the server does not have and every local call 404s.
        """
        monkeypatch.setattr(llm_client, "LOCAL_SQL_BASE_URL", "http://gpu:8080/v1")
        monkeypatch.setattr(llm_client, "LOCAL_PROSE_BASE_URL", "http://gpu:8080/v1")
        monkeypatch.setattr(llm_client, "LOCAL_SQL_MODEL", "Foundation-Sec")
        monkeypatch.setattr(llm_client, "LOCAL_PROSE_MODEL", "Foundation-Sec")
        monkeypatch.setattr(local_models, "SUPERVISOR_URL", "")
        client_factory(FakeClient({"/models": FakeResponse(
            200, {"data": [{"id": "AQLight"}]})}))

        inv = asyncio.run(local_models.inventory())

        assert inv["roles"]["sqlgen"]["reachable"] is True
        assert inv["roles"]["sqlgen"]["healthy"] is False

    def test_an_unreachable_endpoint_is_reported_not_raised(self, client_factory, monkeypatch):
        """The CPU box is the normal case for this path, not an error."""
        monkeypatch.setattr(llm_client, "LOCAL_SQL_BASE_URL", "http://gpu:8080/v1")
        monkeypatch.setattr(llm_client, "LOCAL_PROSE_BASE_URL", "http://gpu:8080/v1")
        monkeypatch.setattr(local_models, "SUPERVISOR_URL", "")
        client_factory(FakeClient(raise_on={"/models"}))

        inv = asyncio.run(local_models.inventory())

        assert inv["roles"]["prose"]["reachable"] is False
        assert inv["roles"]["prose"]["error"]
        assert inv["roles"]["prose"]["serving"] == []

    def test_no_endpoint_configured_is_not_an_error(self, client_factory, monkeypatch):
        monkeypatch.setattr(llm_client, "LOCAL_SQL_BASE_URL", "")
        monkeypatch.setattr(llm_client, "LOCAL_PROSE_BASE_URL", "")
        monkeypatch.setattr(local_models, "SUPERVISOR_URL", "")
        client_factory(FakeClient())

        inv = asyncio.run(local_models.inventory())

        assert inv["roles"]["sqlgen"]["reachable"] is False
        assert "no endpoint" in inv["roles"]["sqlgen"]["error"]

    def test_no_supervisor_renders_read_only_rather_than_failing(self, client_factory, monkeypatch):
        monkeypatch.setattr(local_models, "SUPERVISOR_URL", "")
        client_factory(FakeClient())

        sup = asyncio.run(local_models.inventory())["supervisor"]

        assert sup["available"] is False
        assert sup["reason"]
        assert sup["allowlist"] == []

    def test_an_unreachable_supervisor_is_also_read_only(self, client_factory, monkeypatch):
        monkeypatch.setattr(local_models, "SUPERVISOR_URL", "http://host:8790")
        client_factory(FakeClient(raise_on={"8790"}))

        sup = asyncio.run(local_models.inventory())["supervisor"]

        assert sup["available"] is False

    def test_the_supervisor_allowlist_is_surfaced(self, client_factory, monkeypatch):
        monkeypatch.setattr(local_models, "SUPERVISOR_URL", "http://host:8790")
        client_factory(FakeClient({"8790": FakeResponse(200, {
            "allowlist": ["aqlight", "foundation-sec"],
            "units": {"aqlight": {"active": True}},
        })}))

        sup = asyncio.run(local_models.inventory())["supervisor"]

        assert sup["available"] is True
        assert "foundation-sec" in sup["allowlist"]


class TestControlBoundary:
    """What may and may not cross to the host. The point of the whole design."""

    @pytest.mark.parametrize("bad", [
        "../../etc/passwd",
        "/opt/models/evil.gguf",
        "aqlight/../../root",
        "windows\\path",
    ])
    def test_a_path_is_refused_before_it_reaches_the_host(self, client_factory, monkeypatch, bad):
        """Belt and braces over the supervisor's own allowlist.

        The supervisor is the real boundary, but a key with a separator in it is never
        legitimate and should not travel at all.
        """
        monkeypatch.setattr(local_models, "SUPERVISOR_URL", "http://host:8790")
        client = client_factory(FakeClient({"8790": FakeResponse(200, {"ok": True})}))

        with pytest.raises(local_models.ModelControlError) as exc:
            asyncio.run(local_models.start("prose", bad))

        assert exc.value.status == 400
        assert client.posts == [], "nothing should have been sent to the host"

    def test_an_empty_model_is_refused(self, client_factory, monkeypatch):
        monkeypatch.setattr(local_models, "SUPERVISOR_URL", "http://host:8790")
        client = client_factory(FakeClient())
        with pytest.raises(local_models.ModelControlError):
            asyncio.run(local_models.start("prose", ""))
        assert client.posts == []

    def test_an_unknown_role_is_refused(self, client_factory, monkeypatch):
        monkeypatch.setattr(local_models, "SUPERVISOR_URL", "http://host:8790")
        client = client_factory(FakeClient())
        with pytest.raises(local_models.ModelControlError) as exc:
            asyncio.run(local_models.start("root", "aqlight"))
        assert exc.value.status == 400
        assert client.posts == []

    def test_only_role_and_model_are_sent(self, client_factory, monkeypatch):
        """No paths, ports, flags or commands in the payload. Ever."""
        monkeypatch.setattr(local_models, "SUPERVISOR_URL", "http://host:8790")
        client = client_factory(FakeClient({"8790": FakeResponse(200, {"ok": True})}))

        asyncio.run(local_models.start("prose", "foundation-sec"))

        url, payload = client.posts[0]
        assert url.endswith("/start")
        assert set(payload) == {"role", "model"}
        assert payload == {"role": "prose", "model": "foundation-sec"}


class TestControlFailures:
    def test_no_supervisor_configured_is_a_501_not_a_crash(self, client_factory, monkeypatch):
        """"This box cannot do that" is a different message from "that failed"."""
        monkeypatch.setattr(local_models, "SUPERVISOR_URL", "")
        client_factory(FakeClient())
        with pytest.raises(local_models.ModelControlError) as exc:
            asyncio.run(local_models.start("prose", "aqlight"))
        assert exc.value.status == 501

    def test_an_unreachable_supervisor_is_a_502(self, client_factory, monkeypatch):
        monkeypatch.setattr(local_models, "SUPERVISOR_URL", "http://host:8790")
        client_factory(FakeClient(raise_on={"8790"}))
        with pytest.raises(local_models.ModelControlError) as exc:
            asyncio.run(local_models.start("prose", "aqlight"))
        assert exc.value.status == 502

    def test_a_refusal_is_passed_through_verbatim(self, client_factory, monkeypatch):
        """"Not allowlisted" must reach the operator as that, not as a generic error.

        Otherwise they retry a click that can never work.
        """
        monkeypatch.setattr(local_models, "SUPERVISOR_URL", "http://host:8790")
        client_factory(FakeClient({"8790": FakeResponse(
            400, {"detail": "model 'llama9' is not allowlisted"})}))

        with pytest.raises(local_models.ModelControlError) as exc:
            asyncio.run(local_models.start("prose", "llama9"))

        assert exc.value.status == 400
        assert "not allowlisted" in str(exc.value)

    def test_a_supervisor_5xx_becomes_a_502(self, client_factory, monkeypatch):
        """Its internal failure is our upstream failure, not a client error."""
        monkeypatch.setattr(local_models, "SUPERVISOR_URL", "http://host:8790")
        client_factory(FakeClient({"8790": FakeResponse(500, {"detail": "systemctl blew up"})}))
        with pytest.raises(local_models.ModelControlError) as exc:
            asyncio.run(local_models.stop("prose"))
        assert exc.value.status == 502

    def test_stop_sends_only_the_role(self, client_factory, monkeypatch):
        monkeypatch.setattr(local_models, "SUPERVISOR_URL", "http://host:8790")
        client = client_factory(FakeClient({"8790": FakeResponse(200, {"ok": True})}))
        asyncio.run(local_models.stop("prose"))
        url, payload = client.posts[0]
        assert url.endswith("/stop")
        assert payload == {"role": "prose"}


class TestAuth:
    def test_the_supervisor_token_is_sent_when_set(self, client_factory, monkeypatch):
        monkeypatch.setattr(local_models, "SUPERVISOR_TOKEN", "s3cret")
        assert local_models._headers() == {"Authorization": "Bearer s3cret"}

    def test_no_token_sends_no_header(self, monkeypatch):
        """Rather than an empty bearer, which the supervisor would have to special-case."""
        monkeypatch.setattr(local_models, "SUPERVISOR_TOKEN", "")
        assert local_models._headers() == {}
