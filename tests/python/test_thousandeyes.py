"""
ThousandEyes monitoring-feed regression (sweep-4 ql-4, sweep-5 reg check).

The FIX: a FAILED test-inventory fetch (auth/403/5xx/network) must be reported
as monitoring_available=False; NOT collapsed to an empty list that reads as
"all clear / no tests configured". A dead monitoring feed reading green is the
dangerous regression this locks in.

  * fetch_all_tests returns None on fetch failure (not []).
  * fetch_all_tests handles a client that raises without crashing.
  * gather_te_context maps None inventory -> monitoring_available=False (never all-clear).
  * a genuinely-empty (but successful) inventory is distinct: note "no tests configured".

httpx is fully stubbed; no network. All functions imported from the real module.
"""

from __future__ import annotations

import asyncio

import pytest

from conftest import load_agent_main

_te = load_agent_main("thousandeyes-analyst", "te_main")


class _RaisingClient:
    """Stand-in httpx.AsyncClient whose .get always raises (simulates 5xx/network)."""

    async def get(self, *args, **kwargs):
        raise RuntimeError("boom: monitoring feed unreachable")


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _OkClient:
    """Returns a canned /tests payload; no pagination."""

    def __init__(self, payload):
        self._payload = payload
        self.calls = 0

    async def get(self, url, *args, **kwargs):
        self.calls += 1
        return _FakeResp(self._payload)


# ---------------------------------------------------------------------------
# fetch_all_tests
# ---------------------------------------------------------------------------

def test_fetch_all_tests_returns_none_on_failure():
    """REVERT-CHECK: the pre-fix code caught the error and returned []; which
    downstream reads as 'zero tests configured' (all clear). Returning None is
    the fix; asserting `is None` catches a revert to []."""
    result = asyncio.run(_te.fetch_all_tests(_RaisingClient()))
    assert result is None


def test_fetch_all_tests_empty_success_is_empty_list_not_none():
    """A SUCCESSFUL fetch with zero tests is an empty list (distinct from the
    None failure signal)."""
    result = asyncio.run(_te.fetch_all_tests(_OkClient({"tests": []})))
    assert result == []
    assert result is not None


def test_fetch_all_tests_filters_disabled():
    payload = {"tests": [
        {"testId": 1, "enabled": True},
        {"testId": 2, "enabled": False},
        {"testId": 3},  # default enabled=True
    ]}
    result = asyncio.run(_te.fetch_all_tests(_OkClient(payload)))
    ids = {t["testId"] for t in result}
    assert ids == {1, 3}


# ---------------------------------------------------------------------------
# gather_te_context
# ---------------------------------------------------------------------------

def test_gather_context_no_token_is_monitoring_unavailable(monkeypatch):
    monkeypatch.setattr(_te, "TE_BEARER_TOKEN", "")
    ctx = asyncio.run(_te.gather_te_context("how's the network?"))
    assert ctx["monitoring_available"] is False


def test_gather_context_failed_inventory_is_not_all_clear(monkeypatch):
    """The core ql-4 lock-in: token present, but the inventory fetch FAILS
    (fetch_all_tests -> None). Context must say monitoring_available=False and
    must NOT read as a healthy all-clear (no green_count implying health).

    REVERT-CHECK: if fetch_all_tests regressed to [] OR gather_te_context
    stopped special-casing `tests is None`, this would fall into the
    'no tests configured' / healthy path and monitoring_available would be
    absent/True. Asserting False here catches it.
    """
    monkeypatch.setattr(_te, "TE_BEARER_TOKEN", "fake-token")

    async def _none_tests(client):
        return None

    async def _no_alerts(client):
        return []

    monkeypatch.setattr(_te, "fetch_all_tests", _none_tests)
    monkeypatch.setattr(_te, "fetch_alerts", _no_alerts)

    ctx = asyncio.run(_te.gather_te_context("everything ok?"))
    assert ctx["monitoring_available"] is False
    assert ctx.get("total_tests", 0) == 0
    # Must not present as healthy: no green tests, no all-clear note.
    assert "green_count" not in ctx
    assert ctx.get("note") != "no tests configured"


def test_gather_context_empty_but_successful_inventory_is_no_tests_note(monkeypatch):
    """Distinct from failure: a successful-but-empty inventory yields the
    'no tests configured' note and does NOT set monitoring_available=False."""
    monkeypatch.setattr(_te, "TE_BEARER_TOKEN", "fake-token")

    async def _empty_tests(client):
        return []

    async def _no_alerts(client):
        return []

    monkeypatch.setattr(_te, "fetch_all_tests", _empty_tests)
    monkeypatch.setattr(_te, "fetch_alerts", _no_alerts)

    ctx = asyncio.run(_te.gather_te_context("everything ok?"))
    assert ctx.get("note") == "no tests configured"
    assert "monitoring_available" not in ctx  # not a dead feed


def test_fetch_alerts_returns_none_on_failure():
    """REVERT-CHECK: fetch_alerts used to catch the error and return [], which
    reads downstream as 'checked, zero active alerts' (false all-clear) instead
    of 'the alert feed could not be queried'. None is the fix."""
    result = asyncio.run(_te.fetch_alerts(_RaisingClient()))
    assert result is None


def test_fetch_alerts_empty_success_is_empty_list_not_none():
    result = asyncio.run(_te.fetch_alerts(_OkClient({"alerts": []})))
    assert result == []
    assert result is not None


def test_gather_context_failed_alerts_is_not_all_clear(monkeypatch):
    """The alerts-fetch counterpart of the inventory ql-4 lock-in: tests are
    healthy, but the alert feed itself failed (fetch_alerts -> None). Context
    must set alerts_available=False, not silently report zero alerts as clean.
    """
    monkeypatch.setattr(_te, "TE_BEARER_TOKEN", "fake-token")

    async def _empty_tests(client):
        return []

    async def _failed_alerts(client):
        return None

    monkeypatch.setattr(_te, "fetch_all_tests", _empty_tests)
    monkeypatch.setattr(_te, "fetch_alerts", _failed_alerts)

    ctx = asyncio.run(_te.gather_te_context("everything ok?"))
    assert ctx["alerts_available"] is False
    assert ctx["active_alert_count"] == 0


def test_fetch_latest_results_none_handled(monkeypatch):
    """fetch returning nothing usable must not crash aggregation: a client that
    returns empty results yields {} rather than raising."""
    result = asyncio.run(
        _te.fetch_latest_results(_OkClient({"results": []}), 123, "network")
    )
    assert result == {}
