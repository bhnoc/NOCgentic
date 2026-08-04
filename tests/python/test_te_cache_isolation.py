"""Guards conftest._cold_te_cache.

thousandeyes-analyst caches by `id(client)` for non-httpx clients. CPython
recycles addresses, so a leaked entry can be served to a later, unrelated stub
while the 30s TTL is open -- the stub's .get is never called and it silently
inherits the previous test's payload. That made test_thousandeyes.py pass
locally and fail in CI (test_fetch_all_tests_filters_disabled saw the [] left
by test_fetch_all_tests_empty_success_*).

Asserting the invariant (each test starts cold) rather than trying to win the
allocator race, which is exactly the nondeterminism being removed.
"""

from __future__ import annotations

import asyncio

from conftest import load_agent_main

_te = load_agent_main("thousandeyes-analyst", "te_main")


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _OkClient:
    def __init__(self, payload):
        self._payload = payload
        self.calls = 0

    async def get(self, url, *args, **kwargs):
        self.calls += 1
        return _FakeResp(self._payload)


def test_a_leaves_an_entry_in_the_te_cache():
    """Precondition: a fetch through a stub really does populate the cache."""
    client = _OkClient({"tests": []})
    assert asyncio.run(_te.fetch_all_tests(client)) == []
    assert _te._te_cache, "expected fetch_all_tests to cache under client prefix"


def test_b_starts_with_a_cold_cache():
    """The autouse fixture must have wiped what test_a left behind."""
    assert _te._te_cache == {}, (
        "thousandeyes TTL cache leaked across tests; an id(client) collision can "
        "then serve one stub's payload to another (see conftest._cold_te_cache)"
    )


def test_c_address_recycling_isolation():
    """Even if two distinct stub objects happen to occupy the same memory address
    due to CPython address recycling, they must not share cache entries."""
    client1 = _OkClient({"tests": [{"testId": 100}]})
    res1 = asyncio.run(_te.fetch_all_tests(client1))
    assert res1 == [{"testId": 100}]
    assert client1.calls == 1

    client2 = _OkClient({"tests": [{"testId": 200}]})
    res2 = asyncio.run(_te.fetch_all_tests(client2))
    assert res2 == [{"testId": 200}]
    assert client2.calls == 1
