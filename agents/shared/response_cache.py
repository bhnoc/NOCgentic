"""Redis-backed cache for finished agent answers, shared across replicas.

WHY REDIS AND NOT ANOTHER IN-PROCESS DICT
-----------------------------------------
There are already several in-process caches here (athena_client._query_cache,
the orchestrator's _hints_cache and _lane_store). They all die with the container
and none of them are visible to a second replica. The booth pattern this exists
for -- an attendee clicks a quick-pick chip that somebody else clicked ninety
seconds ago -- has to hit whichever orchestrator happens to answer, and has to
survive the redeploys that happen constantly during a show. That needs shared
state, so: Redis.

This sits ABOVE athena_client's SQL cache and caches something different. That
one caches `SQL -> rows`, saving the Athena scan but still paying for NL->SQL
generation and the whole prose write-up. This caches `question -> finished
answer`, which is where the seconds actually are.

WHERE IT IS SAFE TO CALL THIS, WHICH IS NARROWER THAN IT LOOKS
-------------------------------------------------------------
The cache key is the query text and nothing else. No session, no client IP. That
is deliberate -- an answer that only ever came back to the person who asked for
it first would be pointless -- but it means a cached entry WILL be served to a
different caller than the one who populated it. So this may only be called from a
point where the response is a function of the query text alone.

In the orchestrator that point is after every guardrail has run: quarantine,
restricted-range, the refusal classifier and the Athena kill-switch all return
their cover response BEFORE the cache is consulted. Caching those would be a
security bug in four separate ways.

  * Quarantine is per-session. Replaying a contained session's cover to everyone
    is a leak; serving a cached real answer TO a contained session silently
    defeats Manifold containment.
  * Refusal is an LLM verdict, so it is not deterministic for a fixed string. A
    cache would freeze one roll of the classifier forever.
  * The kill-switch is an admin toggle that gets flipped mid-incident. A cache
    populated before the flip would keep serving live answers after it.
  * Cover responses are built to be indistinguishable from real answers. A cover
    returned from Redis in two milliseconds next to a genuine answer that takes
    eight seconds turns latency into a guardrail oracle.

That last point applies to ordinary cache hits too, which is what HIT_DELAY
below is about.

FAIL-OPEN, ALWAYS
-----------------
Every operation swallows its own exceptions and reports a miss. Redis being down,
slow, full or misconfigured degrades this to "no cache" and never to "no answers".
A cache is an optimisation; the show does not stop because an optimisation is
unavailable.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from typing import Any

import pacing

logger = logging.getLogger(__name__)

# redis is an optional dependency. A box without it (or with an older image mid
# rollout) runs uncached rather than failing to import the orchestrator.
try:                                            # pragma: no cover - import guard
    from redis import asyncio as aioredis
except Exception:                               # pragma: no cover - import guard
    aioredis = None  # type: ignore[assignment]


CACHE_ENABLED: bool = os.getenv("RESPONSE_CACHE_ENABLED", "true").strip().lower() not in (
    "false", "0", "no", "off",
)

REDIS_URL: str = os.getenv("REDIS_URL", "redis://redis:6379/0")

# TTL. Longer than athena_client's 300s because what is being cached is more
# expensive to rebuild, and the answers are narrative summaries of a window of
# activity rather than raw rows -- a fifteen-minute-old summary of "highest
# severity threats today" is still a true answer to that question. Shorten it for
# a show where freshness beats hit rate.
TTL_SECONDS: int = int(os.getenv("RESPONSE_CACHE_TTL_SECONDS", "900"))

# A cached answer must not come back faster than a real one, or response time
# becomes a side channel: an observer who can tell "cached" from "computed" can
# tell which questions have been asked before, and the same reasoning applied to
# cover responses would let them tell a filtered question from an answered one.
#
# So a hit is padded to a plausible total wall-clock, drawn uniformly rather than
# fixed -- a constant 3.000s would be a tell of its own, and identical timings
# across two requests are exactly the pattern that gives a cache away. The window
# is chosen to sit inside the spread of genuine answers (cloud lane measured at
# ~8.7s end to end, faster for simple lookups) while still being a visible speedup.
#
# This is a TARGET TOTAL, not an added delay: the padding subtracts whatever the
# request has already spent, so a hit lands at 2-5s from the caller's point of
# view instead of 2-5s on top of classification.
HIT_DELAY_MIN_SECONDS: float = float(os.getenv("RESPONSE_CACHE_HIT_DELAY_MIN", "2.0"))
HIT_DELAY_MAX_SECONDS: float = float(os.getenv("RESPONSE_CACHE_HIT_DELAY_MAX", "5.0"))

# Bumped when the cached payload's shape changes. Old entries then miss instead of
# deserialising into something the current code misreads.
_SCHEMA_VERSION = "v1"
_KEY_PREFIX = f"bhnoc:answer:{_SCHEMA_VERSION}:"

# Operations are wrapped in a timeout so a hung Redis costs milliseconds, not the
# request. A cache lookup that takes longer than this has already failed at its
# only job.
_OP_TIMEOUT_SECONDS = 0.75

_client: Any = None
_client_loop: asyncio.AbstractEventLoop | None = None

_WHITESPACE_RE = re.compile(r"\s+")


def _normalise(query: str) -> str:
    """Collapse the cosmetic differences between two askings of one question.

    Case and internal whitespace only, plus trailing punctuation. Deliberately
    NOT stemming, stopword removal or synonym folding: those would make two
    genuinely different questions collide, and a wrong cached answer is far worse
    than a missed cache. "port 445 scanners" and "port 4450 scanners" must stay
    distinct.
    """
    return _WHITESPACE_RE.sub(" ", query.strip().lower()).rstrip("?!. ")


def cache_key(query: str, *, agent: str, lane_fingerprint: str = "") -> str:
    """Key for one (question, answering agent) pair.

    `agent` is part of the key because the same words routed to alert-triage and
    to athena-hunter are two different questions with two different answers, and
    classification is an LLM call that can legitimately land differently.

    `lane_fingerprint` lets a box whose model config has changed miss rather than
    serve an answer attributed to a model it no longer runs.

    The query is hashed, not stored in the key: keys end up in Redis logs,
    SLOWLOG and `KEYS` output, and queries can contain IPs and hostnames from the
    conference network. The plaintext is not in the value either -- see `put`.
    """
    material = f"{_normalise(query)}\x00{agent}\x00{lane_fingerprint}"
    return _KEY_PREFIX + hashlib.sha256(material.encode("utf-8")).hexdigest()


def _get_client() -> Any:
    """Lazily build the client, rebinding if the event loop changed.

    Same hazard as the boto3 rule in CLAUDE.md, different mechanism: a redis
    asyncio client pins itself to the loop it was created on, so a module-level
    singleton built at import time breaks under uvicorn's loop and again in tests
    that each run their own `asyncio.run`.
    """
    global _client, _client_loop
    if aioredis is None:
        return None
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return None
    if _client is not None and _client_loop is loop:
        return _client
    _client = aioredis.from_url(
        REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
        socket_timeout=_OP_TIMEOUT_SECONDS,
        socket_connect_timeout=_OP_TIMEOUT_SECONDS,
        # A cache that retries is a cache that adds latency to the path it exists
        # to speed up. One shot, then miss.
        retry_on_timeout=False,
        health_check_interval=30,
    )
    _client_loop = loop
    return _client


async def get(key: str) -> dict[str, Any] | None:
    """Return the cached payload, or None on miss, expiry or any failure."""
    if not CACHE_ENABLED:
        return None
    client = _get_client()
    if client is None:
        return None
    try:
        raw = await asyncio.wait_for(client.get(key), timeout=_OP_TIMEOUT_SECONDS)
    except Exception as exc:
        logger.debug("response cache get failed (serving uncached): %s", exc)
        return None
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except Exception:
        # Corrupt or written by an incompatible build. Drop it rather than letting
        # one bad value poison this key until the TTL expires.
        logger.warning("response cache entry was not valid JSON; discarding")
        await delete(key)
        return None
    if not isinstance(payload, dict):
        await delete(key)
        return None
    return payload


async def put(key: str, payload: dict[str, Any]) -> bool:
    """Store a payload under the TTL. True if it landed.

    The caller owns what goes in here. Two rules, both enforced at the call site
    because only the caller knows: never store a cover response, and never store
    an error. An error is a transient condition about one attempt, and caching it
    would turn one unreachable-agent blip into fifteen minutes of them.
    """
    if not CACHE_ENABLED:
        return False
    client = _get_client()
    if client is None:
        return False
    try:
        blob = json.dumps(payload, default=str)
    except Exception as exc:
        logger.warning("response cache payload was not serialisable: %s", exc)
        return False
    try:
        await asyncio.wait_for(
            client.set(key, blob, ex=TTL_SECONDS), timeout=_OP_TIMEOUT_SECONDS,
        )
        return True
    except Exception as exc:
        logger.debug("response cache put failed (answer still served): %s", exc)
        return False


async def delete(key: str) -> None:
    """Best-effort invalidation of one key."""
    client = _get_client()
    if client is None:
        return
    try:
        await asyncio.wait_for(client.delete(key), timeout=_OP_TIMEOUT_SECONDS)
    except Exception as exc:
        logger.debug("response cache delete failed: %s", exc)


async def purge() -> int:
    """Drop every entry this build owns. Returns the number of keys removed.

    Scoped to the prefix with SCAN rather than FLUSHDB, so it cannot take out
    anything else sharing the instance, and does not block Redis on a big keyspace.
    """
    client = _get_client()
    if client is None:
        return 0
    removed = 0
    try:
        async for key in client.scan_iter(match=_KEY_PREFIX + "*", count=200):
            try:
                removed += await asyncio.wait_for(
                    client.delete(key), timeout=_OP_TIMEOUT_SECONDS,
                )
            except Exception:
                continue
    except Exception as exc:
        logger.warning("response cache purge failed after %d keys: %s", removed, exc)
    return removed


def hit_delay_seconds(elapsed_seconds: float) -> float:
    """Seconds to wait so a cache hit lands at a plausible total wall-clock.

    The arithmetic lives in `pacing` because the deter path needs the same thing
    with a different window, and two copies of a timing-side-channel defence is
    one copy too many. This function keeps the cache's own policy: which bounds
    apply, read at call time so a monkeypatched env still takes effect.
    """
    return pacing.delay_for_window(
        elapsed_seconds, HIT_DELAY_MIN_SECONDS, HIT_DELAY_MAX_SECONDS,
    )


async def pace_hit(elapsed_seconds: float) -> float:
    """Sleep out the padding for a hit. Returns the seconds actually waited."""
    return await pacing.pace(
        elapsed_seconds, HIT_DELAY_MIN_SECONDS, HIT_DELAY_MAX_SECONDS,
    )


async def health() -> dict[str, Any]:
    """Cache state for the admin surface. Never raises."""
    state: dict[str, Any] = {
        "enabled": CACHE_ENABLED,
        "url": re.sub(r"://[^@/]*@", "://***@", REDIS_URL),
        "ttl_seconds": TTL_SECONDS,
        "hit_delay_window": [HIT_DELAY_MIN_SECONDS, HIT_DELAY_MAX_SECONDS],
        "driver": "redis.asyncio" if aioredis is not None else "missing",
        "connected": False,
        "entries": None,
    }
    client = _get_client()
    if client is None:
        return state
    try:
        started = time.monotonic()
        await asyncio.wait_for(client.ping(), timeout=_OP_TIMEOUT_SECONDS)
        state["connected"] = True
        state["ping_ms"] = round((time.monotonic() - started) * 1000, 2)
    except Exception as exc:
        state["error"] = str(exc)
        return state
    try:
        count = 0
        async for _ in client.scan_iter(match=_KEY_PREFIX + "*", count=500):
            count += 1
        state["entries"] = count
    except Exception:
        pass
    return state


def reset_client_for_test() -> None:
    """Drop the memoised client so a test can swap REDIS_URL or the fake."""
    global _client, _client_loop
    _client = None
    _client_loop = None
