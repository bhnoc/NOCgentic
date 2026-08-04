"""Redis-backed response cache (agents/shared/response_cache.py + orchestrator wiring).

The cache key is the query text and nothing else, which means an entry populated by
one caller IS served to another. That single fact is what every test here is really
about, because it makes correctness of PLACEMENT a security property rather than a
performance one:

  * Nothing that went through _serve_cover may ever be stored. Quarantine, the
    restricted-range filter, the refusal classifier and the Athena kill-switch all
    return through it, and each one caches into a different kind of bug: replaying a
    contained session's cover to everyone, freezing one roll of a non-deterministic
    classifier, or serving live answers after an operator hit the kill-switch.
  * A hit must not come back faster than a real answer. If it does, response time
    tells an observer which questions have been asked before, and the same reasoning
    applied to covers would distinguish a filtered question from an answered one.
  * Redis being unavailable must degrade to "no cache", never to "no answer".

A fake client is used rather than fakeredis or a live server: it keeps the suite
installable with no new dependency, and it still exercises the real JSON
serialisation, TTL and key-derivation paths. What it does NOT cover is genuine Redis
semantics, so `test_ttl_is_passed_to_redis` asserts on the argument we hand the
driver instead of on expiry actually happening.
"""

from __future__ import annotations

import asyncio
import json

import pytest

import response_cache
from conftest import load_agent_main

_orch = load_agent_main("orchestrator", "orch_main_cache")


# ---------------------------------------------------------------------------
# Fake redis.asyncio client
# ---------------------------------------------------------------------------

class FakeRedis:
    """Enough of redis.asyncio to exercise the module. Records calls."""

    def __init__(self, *, fail: bool = False, hang: bool = False):
        self.store: dict[str, str] = {}
        self.ttls: dict[str, int] = {}
        self.fail = fail
        self.hang = hang
        self.calls: list[tuple[str, str]] = []

    async def _maybe_break(self, op: str, key: str = "") -> None:
        self.calls.append((op, key))
        if self.hang:
            await asyncio.sleep(30)          # far beyond the module's op timeout
        if self.fail:
            raise ConnectionError("fake redis is down")

    async def get(self, key):
        await self._maybe_break("get", key)
        return self.store.get(key)

    async def set(self, key, value, ex=None):
        await self._maybe_break("set", key)
        self.store[key] = value
        if ex is not None:
            self.ttls[key] = ex
        return True

    async def delete(self, *keys):
        await self._maybe_break("delete", keys[0] if keys else "")
        return sum(1 for k in keys if self.store.pop(k, None) is not None)

    async def ping(self):
        await self._maybe_break("ping")
        return True

    async def scan_iter(self, match=None, count=None):
        await self._maybe_break("scan", match or "")
        prefix = (match or "").rstrip("*")
        for key in list(self.store):
            if key.startswith(prefix):
                yield key


@pytest.fixture
def fake(monkeypatch):
    """Install a fake client and restore module state afterwards."""
    client = FakeRedis()
    monkeypatch.setattr(response_cache, "_get_client", lambda: client)
    monkeypatch.setattr(response_cache, "CACHE_ENABLED", True)
    yield client
    response_cache.reset_client_for_test()


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

class TestCacheKey:
    def test_same_question_same_key(self):
        a = response_cache.cache_key("port 445 scanners", agent="athena-hunter")
        b = response_cache.cache_key("port 445 scanners", agent="athena-hunter")
        assert a == b

    @pytest.mark.parametrize("variant", [
        "What are the highest-severity threats active right now?",
        "what are the highest-severity threats active right now",
        "  What are the highest-severity threats active right now?  ",
        "What are the highest-severity   threats active right now?",
        "WHAT ARE THE HIGHEST-SEVERITY THREATS ACTIVE RIGHT NOW",
    ])
    def test_cosmetic_differences_collapse(self, variant):
        """Case, surrounding and internal whitespace, and trailing punctuation.

        The quick-pick chips auto-submit a fixed string, but a human retyping the
        same question will not reproduce it byte for byte.
        """
        canonical = response_cache.cache_key(
            "What are the highest-severity threats active right now?", agent="a")
        assert response_cache.cache_key(variant, agent="a") == canonical

    @pytest.mark.parametrize("other", [
        "port 4450 scanners",          # digits differ
        "port 445 scanner",            # singular; NOT stemmed on purpose
        "port 445 scanners today",
        "port 446 scanners",
    ])
    def test_different_questions_do_not_collide(self, other):
        """Normalisation is deliberately shallow.

        No stemming, no stopword removal, no synonyms: a wrong cached answer is much
        worse than a missed cache, and "445" vs "4450" must never merge.
        """
        assert (response_cache.cache_key(other, agent="a")
                != response_cache.cache_key("port 445 scanners", agent="a"))

    def test_agent_is_part_of_the_key(self):
        """Same words, different agent, different answer.

        Classification is an LLM call and can legitimately land differently, so the
        two must not share a slot.
        """
        assert (response_cache.cache_key("q", agent="alert-triage")
                != response_cache.cache_key("q", agent="athena-hunter"))

    def test_lane_fingerprint_is_part_of_the_key(self):
        """Repointing the local lane must miss, not serve an answer from a model
        this box no longer runs."""
        assert (response_cache.cache_key("q", agent="a", lane_fingerprint="race:X/Y")
                != response_cache.cache_key("q", agent="a", lane_fingerprint="single"))

    def test_query_text_is_not_recoverable_from_the_key(self):
        """Keys reach Redis logs, SLOWLOG and KEYS output.

        Conference queries carry IPs and hostnames, so the key is a digest.
        """
        key = response_cache.cache_key("traffic from 10.220.1.5 to evil.example",
                                       agent="athena-hunter")
        assert "10.220.1.5" not in key
        assert "evil.example" not in key
        assert key.startswith("bhnoc:answer:v1:")


# ---------------------------------------------------------------------------
# Round trip
# ---------------------------------------------------------------------------

class TestRoundTrip:
    def test_put_then_get_returns_the_payload(self, fake):
        key = response_cache.cache_key("q", agent="athena-hunter")
        payload = {"answer": "3 hosts scanning 445", "confidence": 0.8,
                   "data": {"rows": [{"ip": "10.0.0.1"}]}, "agent_used": "athena-hunter"}

        async def drive():
            assert await response_cache.put(key, payload) is True
            return await response_cache.get(key)

        assert asyncio.run(drive()) == payload

    def test_miss_returns_none(self, fake):
        got = asyncio.run(response_cache.get(response_cache.cache_key("never asked", agent="a")))
        assert got is None

    def test_ttl_is_passed_to_redis(self, fake, monkeypatch):
        monkeypatch.setattr(response_cache, "TTL_SECONDS", 900)
        key = response_cache.cache_key("q", agent="a")
        asyncio.run(response_cache.put(key, {"answer": "x"}))
        assert fake.ttls[key] == 900

    def test_corrupt_entry_is_discarded_not_returned(self, fake):
        """A value from an incompatible build must not poison the key for its TTL."""
        key = response_cache.cache_key("q", agent="a")
        fake.store[key] = "{not json at all"

        assert asyncio.run(response_cache.get(key)) is None
        assert key not in fake.store, "the bad value should have been deleted"

    def test_non_dict_entry_is_discarded(self, fake):
        key = response_cache.cache_key("q", agent="a")
        fake.store[key] = json.dumps(["not", "a", "dict"])
        assert asyncio.run(response_cache.get(key)) is None
        assert key not in fake.store

    def test_unserialisable_payload_fails_soft(self, fake):
        """A put that cannot be encoded must not raise into the request path.

        `default=str` rescues most odd values, so this uses a dict key type json
        rejects outright.
        """
        key = response_cache.cache_key("q", agent="a")
        assert asyncio.run(response_cache.put(key, {frozenset({1}): "bad"})) is False
        assert fake.store == {}


# ---------------------------------------------------------------------------
# Fail-open: a broken cache must never break a query
# ---------------------------------------------------------------------------

class TestFailOpen:
    def test_get_on_a_dead_redis_is_a_miss(self, monkeypatch):
        monkeypatch.setattr(response_cache, "_get_client", lambda: FakeRedis(fail=True))
        monkeypatch.setattr(response_cache, "CACHE_ENABLED", True)
        assert asyncio.run(response_cache.get("bhnoc:answer:v1:x")) is None

    def test_put_on_a_dead_redis_reports_failure_without_raising(self, monkeypatch):
        monkeypatch.setattr(response_cache, "_get_client", lambda: FakeRedis(fail=True))
        monkeypatch.setattr(response_cache, "CACHE_ENABLED", True)
        assert asyncio.run(response_cache.put("bhnoc:answer:v1:x", {"answer": "a"})) is False

    def test_a_hung_redis_times_out_instead_of_stalling_the_request(self, monkeypatch):
        """The whole point of a cache is latency. One that hangs must be abandoned."""
        monkeypatch.setattr(response_cache, "_get_client", lambda: FakeRedis(hang=True))
        monkeypatch.setattr(response_cache, "CACHE_ENABLED", True)
        monkeypatch.setattr(response_cache, "_OP_TIMEOUT_SECONDS", 0.05)

        async def drive():
            loop = asyncio.get_running_loop()
            started = loop.time()
            got = await response_cache.get("bhnoc:answer:v1:x")
            return got, loop.time() - started

        got, took = asyncio.run(drive())
        assert got is None
        assert took < 1.0, f"a hung redis blocked the request for {took:.2f}s"

    def test_missing_driver_is_a_no_op(self, monkeypatch):
        """A box without the redis package runs uncached rather than failing to boot."""
        monkeypatch.setattr(response_cache, "aioredis", None)
        response_cache.reset_client_for_test()
        assert response_cache._get_client() is None

    def test_disabled_never_reads_or_writes(self, monkeypatch):
        client = FakeRedis()
        monkeypatch.setattr(response_cache, "_get_client", lambda: client)
        monkeypatch.setattr(response_cache, "CACHE_ENABLED", False)

        async def drive():
            assert await response_cache.get("k") is None
            assert await response_cache.put("k", {"answer": "a"}) is False

        asyncio.run(drive())
        assert client.calls == [], "RESPONSE_CACHE_ENABLED=false must not touch redis"


# ---------------------------------------------------------------------------
# Hit pacing: the timing side channel
# ---------------------------------------------------------------------------

class TestHitPacing:
    def test_delay_lands_inside_the_window(self, monkeypatch):
        monkeypatch.setattr(response_cache, "HIT_DELAY_MIN_SECONDS", 2.0)
        monkeypatch.setattr(response_cache, "HIT_DELAY_MAX_SECONDS", 5.0)
        for _ in range(200):
            assert 0.0 <= response_cache.hit_delay_seconds(0.0) <= 5.0

    def test_delay_is_a_target_total_not_an_added_delay(self, monkeypatch):
        """Padding subtracts time already spent, so a hit lands at 2-5s overall.

        Adding 2-5s on top of classification would make cached answers SLOWER than
        the fast real ones, which is the opposite of the point.
        """
        monkeypatch.setattr(response_cache, "HIT_DELAY_MIN_SECONDS", 3.0)
        monkeypatch.setattr(response_cache, "HIT_DELAY_MAX_SECONDS", 3.0)
        assert response_cache.hit_delay_seconds(0.0) == pytest.approx(3.0)
        assert response_cache.hit_delay_seconds(1.0) == pytest.approx(2.0)
        assert response_cache.hit_delay_seconds(2.5) == pytest.approx(0.5)

    def test_an_already_slow_hit_is_not_padded_further(self, monkeypatch):
        """The tell is answers arriving too EARLY. Never delay past the target."""
        monkeypatch.setattr(response_cache, "HIT_DELAY_MIN_SECONDS", 2.0)
        monkeypatch.setattr(response_cache, "HIT_DELAY_MAX_SECONDS", 5.0)
        assert response_cache.hit_delay_seconds(9.0) == 0.0

    def test_the_delay_is_not_constant(self, monkeypatch):
        """A fixed 3.000s on every hit would itself be a tell.

        Two byte-identical response times are exactly the pattern that gives a
        cache away, which is why the lane-race cover path scales its timings too.
        """
        monkeypatch.setattr(response_cache, "HIT_DELAY_MIN_SECONDS", 2.0)
        monkeypatch.setattr(response_cache, "HIT_DELAY_MAX_SECONDS", 5.0)
        seen = {round(response_cache.hit_delay_seconds(0.0), 4) for _ in range(50)}
        assert len(seen) > 40, f"delays barely varied: {sorted(seen)[:5]}"

    def test_a_reversed_window_is_tolerated(self, monkeypatch):
        """Operator sets MIN above MAX. Serve a sane delay, don't crash the query."""
        monkeypatch.setattr(response_cache, "HIT_DELAY_MIN_SECONDS", 5.0)
        monkeypatch.setattr(response_cache, "HIT_DELAY_MAX_SECONDS", 2.0)
        for _ in range(50):
            assert 2.0 <= response_cache.hit_delay_seconds(0.0) <= 5.0

    def test_zero_window_disables_padding(self, monkeypatch):
        monkeypatch.setattr(response_cache, "HIT_DELAY_MIN_SECONDS", 0.0)
        monkeypatch.setattr(response_cache, "HIT_DELAY_MAX_SECONDS", 0.0)
        assert response_cache.hit_delay_seconds(0.0) == 0.0

    def test_pace_hit_actually_waits(self, monkeypatch):
        monkeypatch.setattr(response_cache, "HIT_DELAY_MIN_SECONDS", 0.05)
        monkeypatch.setattr(response_cache, "HIT_DELAY_MAX_SECONDS", 0.05)

        async def drive():
            loop = asyncio.get_running_loop()
            started = loop.time()
            waited = await response_cache.pace_hit(0.0)
            return waited, loop.time() - started

        waited, actual = asyncio.run(drive())
        assert waited == pytest.approx(0.05, abs=0.01)
        assert actual >= 0.04

    def test_pacing_does_not_block_the_event_loop(self, monkeypatch):
        """asyncio.sleep, not time.sleep: other requests keep being served.

        A blocking sleep here would serialise every concurrent query behind each
        cache hit, turning an optimisation into a throughput cliff.
        """
        monkeypatch.setattr(response_cache, "HIT_DELAY_MIN_SECONDS", 0.2)
        monkeypatch.setattr(response_cache, "HIT_DELAY_MAX_SECONDS", 0.2)

        async def drive():
            loop = asyncio.get_running_loop()
            started = loop.time()
            # Ten concurrent hits should overlap, not queue.
            await asyncio.gather(*(response_cache.pace_hit(0.0) for _ in range(10)))
            return loop.time() - started

        assert asyncio.run(drive()) < 1.0


# ---------------------------------------------------------------------------
# Purge
# ---------------------------------------------------------------------------

class TestPurge:
    def test_purge_removes_only_this_builds_keys(self, fake):
        """SCAN over our prefix, not FLUSHDB: the instance may not be ours alone."""
        fake.store["bhnoc:answer:v1:aaa"] = json.dumps({"answer": "a"})
        fake.store["bhnoc:answer:v1:bbb"] = json.dumps({"answer": "b"})
        fake.store["someone:else:key"] = "keep me"

        removed = asyncio.run(response_cache.purge())

        assert removed == 2
        assert fake.store == {"someone:else:key": "keep me"}

    def test_purge_on_a_dead_redis_returns_zero(self, monkeypatch):
        monkeypatch.setattr(response_cache, "_get_client", lambda: FakeRedis(fail=True))
        assert asyncio.run(response_cache.purge()) == 0


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

class TestHealth:
    def test_health_reports_connected_and_counts_entries(self, fake):
        fake.store["bhnoc:answer:v1:aaa"] = json.dumps({"answer": "a"})
        state = asyncio.run(response_cache.health())
        assert state["connected"] is True
        assert state["entries"] == 1
        assert state["ttl_seconds"] == response_cache.TTL_SECONDS

    def test_health_on_a_dead_redis_reports_not_connected(self, monkeypatch):
        monkeypatch.setattr(response_cache, "_get_client", lambda: FakeRedis(fail=True))
        state = asyncio.run(response_cache.health())
        assert state["connected"] is False
        assert "error" in state

    def test_health_masks_credentials_in_the_url(self, monkeypatch):
        monkeypatch.setattr(response_cache, "REDIS_URL", "redis://user:sup3rsecret@redis:6379/0")
        monkeypatch.setattr(response_cache, "_get_client", lambda: None)
        state = asyncio.run(response_cache.health())
        assert "sup3rsecret" not in state["url"]
        assert state["url"] == "redis://***@redis:6379/0"


# ---------------------------------------------------------------------------
# Orchestrator wiring — the placement guarantees
# ---------------------------------------------------------------------------

class TestOrchestratorWiring:
    def test_read_and_write_agree_on_the_key(self, fake, monkeypatch):
        """The writer uses the key the READER computed, never a recomputed one.

        alert-triage folds its parsed `hours` window into the key, so a recomputed
        write key could disagree and populate an entry nothing ever looks up: a
        cache that stores diligently and never hits.
        """
        monkeypatch.setattr(_orch, "_lane_fingerprint", lambda: "single")

        async def call(lane):
            return {"answer": "live answer", "confidence": 0.7, "data": None}

        async def drive():
            result = await _orch._route_cached(
                "job-1", False, "alert-triage", call,
                query="threats\x00hours=48", start=0.0, fallback_confidence=0.5,
            )
            await _orch._store_answer(
                result.get("_cache_key"), "alert-triage",
                answer="live answer", confidence=0.7, data=None,
            )
            # Second identical request must now hit.
            return await _orch._route_cached(
                "job-2", False, "alert-triage", call,
                query="threats\x00hours=48", start=0.0, fallback_confidence=0.5,
            )

        monkeypatch.setattr(response_cache, "HIT_DELAY_MAX_SECONDS", 0.0)
        monkeypatch.setattr(response_cache, "HIT_DELAY_MIN_SECONDS", 0.0)
        second = asyncio.run(drive())
        assert second["_cached"] is True
        assert second["answer"] == "live answer"

    def test_a_different_hours_window_does_not_hit(self, fake, monkeypatch):
        """"last 2 hours" and "last 48 hours" are different questions."""
        monkeypatch.setattr(_orch, "_lane_fingerprint", lambda: "single")
        monkeypatch.setattr(response_cache, "HIT_DELAY_MAX_SECONDS", 0.0)
        monkeypatch.setattr(response_cache, "HIT_DELAY_MIN_SECONDS", 0.0)
        calls: list[str] = []

        async def call(lane):
            calls.append("live")
            return {"answer": "a", "confidence": 0.7, "data": None}

        async def drive():
            r = await _orch._route_cached("j1", False, "alert-triage", call,
                                          query="threats\x00hours=2", start=0.0,
                                          fallback_confidence=0.5)
            await _orch._store_answer(r["_cache_key"], "alert-triage",
                                      answer="a", confidence=0.7, data=None)
            await _orch._route_cached("j2", False, "alert-triage", call,
                                      query="threats\x00hours=48", start=0.0,
                                      fallback_confidence=0.5)

        asyncio.run(drive())
        assert calls == ["live", "live"], "the 48h query should not reuse the 2h answer"

    def test_a_hit_does_not_call_the_agent(self, fake, monkeypatch):
        monkeypatch.setattr(_orch, "_lane_fingerprint", lambda: "single")
        monkeypatch.setattr(response_cache, "HIT_DELAY_MAX_SECONDS", 0.0)
        monkeypatch.setattr(response_cache, "HIT_DELAY_MIN_SECONDS", 0.0)
        calls: list[str] = []

        async def call(lane):
            calls.append("live")
            return {"answer": "live", "confidence": 0.7, "data": None}

        async def drive():
            r = await _orch._route_cached("j1", False, "athena-hunter", call,
                                          query="q", start=0.0, fallback_confidence=0.5)
            await _orch._store_answer(r["_cache_key"], "athena-hunter",
                                      answer="live", confidence=0.7, data=None)
            return await _orch._route_cached("j2", False, "athena-hunter", call,
                                             query="q", start=0.0, fallback_confidence=0.5)

        hit = asyncio.run(drive())
        assert len(calls) == 1, "the second request should not have reached the agent"
        assert hit["_cached"] is True

    def test_a_hit_carries_no_lane_metadata(self, fake, monkeypatch):
        """No race happened, so there is no honest second opinion to swap to.

        Reporting a lane on a cached answer would put a swap control on the UI whose
        timings were invented.
        """
        monkeypatch.setattr(_orch, "_lane_fingerprint", lambda: "single")
        monkeypatch.setattr(response_cache, "HIT_DELAY_MAX_SECONDS", 0.0)
        monkeypatch.setattr(response_cache, "HIT_DELAY_MIN_SECONDS", 0.0)

        async def call(lane):
            return {"answer": "live", "confidence": 0.7, "data": None, "_lane": "cloud"}

        async def drive():
            r = await _orch._route_cached("j1", True, "athena-hunter", call,
                                          query="q", start=0.0, fallback_confidence=0.5)
            await _orch._store_answer(r["_cache_key"], "athena-hunter",
                                      answer="live", confidence=0.7, data=None)
            return await _orch._route_cached("j2", True, "athena-hunter", call,
                                             query="q", start=0.0, fallback_confidence=0.5)

        hit = asyncio.run(drive())
        assert "_lane" not in hit

    def test_errors_are_never_cached(self, fake):
        """One unreachable-agent blip must not become fifteen minutes of them."""
        async def drive():
            await _orch._store_answer("bhnoc:answer:v1:err", "error",
                                      answer="Agent is currently unreachable.",
                                      confidence=0.0, data=None)

        asyncio.run(drive())
        assert fake.store == {}

    def test_empty_answers_are_never_cached(self, fake):
        async def drive():
            await _orch._store_answer("bhnoc:answer:v1:empty", "athena-hunter",
                                      answer="   ", confidence=0.5, data=None)

        asyncio.run(drive())
        assert fake.store == {}

    def test_a_missing_key_is_not_stored(self, fake):
        """_route_cached only attaches a key when it ran; guard the None case."""
        asyncio.run(_orch._store_answer(None, "athena-hunter",
                                        answer="a", confidence=0.5, data=None))
        assert fake.store == {}

    def test_lane_fingerprint_tracks_the_configured_models(self, monkeypatch):
        import llm_client
        monkeypatch.setattr(llm_client, "LANE_RACE", "on")
        monkeypatch.setattr(llm_client, "LOCAL_SQL_MODEL", "AQLight")
        monkeypatch.setattr(llm_client, "LOCAL_PROSE_MODEL", "AQLight")
        one = _orch._lane_fingerprint()
        monkeypatch.setattr(llm_client, "LOCAL_PROSE_MODEL", "Foundation-Sec")
        assert _orch._lane_fingerprint() != one

    def test_lane_fingerprint_distinguishes_racing_from_single(self, monkeypatch):
        import llm_client
        monkeypatch.setattr(llm_client, "LANE_RACE", "off")
        assert _orch._lane_fingerprint() == "single"
        monkeypatch.setattr(llm_client, "LANE_RACE", "on")
        assert _orch._lane_fingerprint() != "single"


# ---------------------------------------------------------------------------
# Placement: cover responses must never reach the cache
# ---------------------------------------------------------------------------

class TestCoverResponsesAreNeverCached:
    """The four cover paths all return BEFORE _route_cached is reached.

    This is asserted structurally rather than by driving handle_query, which would
    need the whole LLM classifier stubbed. If someone moves the cache in front of
    these checks, these tests are what should fail.
    """

    def test_serve_cover_does_not_touch_the_cache(self, fake):
        resp = _orch._serve_cover("anything", start=0.0, salt="quarantine")
        assert resp.answer
        assert fake.calls == [], "a cover response must not read or write the cache"

    @pytest.mark.parametrize("salt", ["quarantine", "refused", "kill_switch", "hints"])
    def test_every_cover_salt_stays_out_of_the_cache(self, fake, salt):
        _orch._serve_cover("q", start=0.0, salt=salt)
        assert fake.store == {}

    def test_cover_paths_return_before_the_cache_in_handle_query(self):
        """Source-order check: each cover early-return precedes the first lookup.

        Crude, and deliberately so. The alternative is stubbing the classifier, both
        lanes and four agents to prove a negative about ordering. What matters is
        that reordering the function trips something.
        """
        import inspect
        src = inspect.getsource(_orch.handle_query)
        first_cache = src.index("_route_cached")
        for marker in ('salt="quarantine"', "_serve_cover(req.query, start=start)",
                       'salt="refused"', 'salt="kill_switch"'):
            assert marker in src, f"cover path {marker} vanished from handle_query"
        # quarantine, restricted and refused all precede any cache lookup.
        assert src.index('salt="quarantine"') < first_cache
        assert src.index("_serve_cover(req.query, start=start)") < first_cache
        assert src.index('salt="refused"') < first_cache
        # The kill-switch sits inside the athena branch, immediately before its
        # own lookup, so compare against the LAST lookup rather than the first.
        assert src.index('salt="kill_switch"') < src.rindex("_route_cached")

    def test_the_cache_is_read_after_classification(self):
        """The agent name is part of the key, so it cannot be read any earlier."""
        import inspect
        src = inspect.getsource(_orch.handle_query)
        first_cache = src.index("_route_cached")
        assert src.index("_classify_raced") < first_cache
        assert src.index("llm_classify") < first_cache

    def test_write_back_happens_after_sanitisation(self):
        """Storing pre-sanitisation text would keep leaking under old redaction
        rules until every entry aged out."""
        import inspect
        src = inspect.getsource(_orch.handle_query)
        assert src.index("sanitize_output_text(answer)") < src.index("_store_answer")
        assert src.index("sanitize_output_obj(data)") < src.index("_store_answer")
