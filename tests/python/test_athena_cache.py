"""Gate for the Athena result cache.

Repeat questions return from cache after a short simulated delay instead of a
full multi-second Athena round trip. The delay is deliberate product behaviour:
an instant answer reads as fake at a booth.

Exercises the real execute_query() with the boto3 layer faked, so no AWS creds
or network are needed. The cache must sit AFTER sanitize_sql and AFTER the scope
row filter, or a hit could serve rows the live path would now reject.
"""

import asyncio
import importlib
import os
import sys
import time

import pytest

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(_ROOT, "agents", "shared"))


class _FakeAthena:
    """Minimal stand-in for the boto3 Athena client, counting real calls."""

    def __init__(self, rows):
        self.calls = 0
        self._rows = rows

    def start_query_execution(self, **kw):
        self.calls += 1
        return {"QueryExecutionId": f"q{self.calls}"}

    def get_query_execution(self, **kw):
        return {"QueryExecution": {
            "Status": {"State": "SUCCEEDED"},
            "Statistics": {"EngineExecutionTimeInMillis": 10, "DataScannedInBytes": 1024},
        }}

    def get_query_results(self, **kw):
        header = [{"VarCharValue": c} for c in self._rows[0]]
        data = [{"Data": header}]
        for r in self._rows[1:]:
            data.append({"Data": [{"VarCharValue": v} for v in r]})
        return {"ResultSet": {"Rows": data,
                              "ResultSetMetadata": {"ColumnInfo": [
                                  {"Name": c} for c in self._rows[0]]}}}


@pytest.fixture
def ac(monkeypatch):
    """Fresh module per test so cache state and env never leak between tests."""
    monkeypatch.setenv("ATHENA_CACHE_ENABLED", "true")
    monkeypatch.setenv("ATHENA_CACHE_HIT_DELAY_SECONDS", "1.5")
    monkeypatch.setenv("ATHENA_CACHE_TTL_SECONDS", "300")
    import athena_client
    importlib.reload(athena_client)
    return athena_client


IN_SCOPE_SQL = "SELECT id_orig_h FROM conn WHERE id_orig_h = '10.220.40.7' LIMIT 10"
ROWS = [["id_orig_h"], ["10.220.40.7"], ["10.220.41.9"]]


def _wire(ac, monkeypatch, rows=ROWS):
    fake = _FakeAthena(rows)
    monkeypatch.setattr(ac, "_get_athena", lambda: fake)
    return fake


def test_second_identical_query_does_not_hit_athena(ac, monkeypatch):
    fake = _wire(ac, monkeypatch)
    rows1, meta1 = asyncio.run(ac.execute_query(IN_SCOPE_SQL))
    rows2, meta2 = asyncio.run(ac.execute_query(IN_SCOPE_SQL))
    assert fake.calls == 1, "cache did not prevent the second Athena call"
    assert rows1 == rows2, "cached rows differ from the cold result"
    assert meta1.get("cached") is False
    assert meta2.get("cached") is True


def test_cache_hit_takes_roughly_the_configured_delay(ac, monkeypatch):
    _wire(ac, monkeypatch)
    asyncio.run(ac.execute_query(IN_SCOPE_SQL))
    start = time.monotonic()
    asyncio.run(ac.execute_query(IN_SCOPE_SQL))
    elapsed = time.monotonic() - start
    assert 1.3 <= elapsed < 3.0, f"hit took {elapsed:.2f}s, expected ~1.5s"


def test_delay_is_configurable_and_async(ac, monkeypatch):
    monkeypatch.setenv("ATHENA_CACHE_HIT_DELAY_SECONDS", "0.1")
    importlib.reload(ac)
    _wire(ac, monkeypatch)

    async def drive():
        await ac.execute_query(IN_SCOPE_SQL)
        start = time.monotonic()
        # Two concurrent hits: if the sleep blocked the loop they would serialize
        # to ~0.2s. Async sleep overlaps them.
        await asyncio.gather(ac.execute_query(IN_SCOPE_SQL), ac.execute_query(IN_SCOPE_SQL))
        return time.monotonic() - start

    elapsed = asyncio.run(drive())
    assert elapsed < 0.18, f"concurrent hits took {elapsed:.3f}s; sleep looks blocking"


def test_distinct_sql_does_not_collide(ac, monkeypatch):
    fake = _wire(ac, monkeypatch)
    asyncio.run(ac.execute_query(IN_SCOPE_SQL))
    asyncio.run(ac.execute_query(IN_SCOPE_SQL.replace("LIMIT 10", "LIMIT 20")))
    assert fake.calls == 2


def test_ttl_expiry_refetches(ac, monkeypatch):
    monkeypatch.setenv("ATHENA_CACHE_TTL_SECONDS", "0")
    importlib.reload(ac)
    fake = _wire(ac, monkeypatch)
    asyncio.run(ac.execute_query(IN_SCOPE_SQL))
    asyncio.run(ac.execute_query(IN_SCOPE_SQL))
    assert fake.calls == 2, "expired entry was served from cache"


def test_disabling_bypasses_the_cache(ac, monkeypatch):
    monkeypatch.setenv("ATHENA_CACHE_ENABLED", "false")
    importlib.reload(ac)
    fake = _wire(ac, monkeypatch)
    asyncio.run(ac.execute_query(IN_SCOPE_SQL))
    _, meta = asyncio.run(ac.execute_query(IN_SCOPE_SQL))
    assert fake.calls == 2
    assert not meta.get("cached")


def test_cache_cannot_bypass_the_scope_filter(ac, monkeypatch):
    """Out-of-scope rows must be filtered on the cold path AND stay filtered on a
    hit. Caching pre-filter rows would turn the cache into a scope bypass."""
    rows = [["id_orig_h"], ["10.220.40.7"], ["10.0.1.63"]]
    _wire(ac, monkeypatch, rows)
    cold, _ = asyncio.run(ac.execute_query(IN_SCOPE_SQL))
    hot, meta = asyncio.run(ac.execute_query(IN_SCOPE_SQL))
    assert meta.get("cached") is True
    assert cold == hot
    flat = str(cold)
    assert "10.0.1.63" not in flat, "out-of-scope row survived"


def test_cache_sits_after_sql_validation(ac, monkeypatch):
    """A rejected query must never be cached, so tightening the rules later can
    not be defeated by a previously-cached entry."""
    _wire(ac, monkeypatch)
    bad = "SELECT * FROM conn WHERE id_orig_h = '10.0.1.63'"
    with pytest.raises(ValueError):
        asyncio.run(ac.execute_query(bad))
    with pytest.raises(ValueError):
        asyncio.run(ac.execute_query(bad))
