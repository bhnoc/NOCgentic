# Response cache (Redis)

Two people at the booth click the same quick-pick chip ninety seconds apart. The
second one should not wait out a full Athena scan and two LLM calls to read an
answer the box already wrote.

The response cache stores finished answers in Redis, keyed on the question. A repeat
question comes back without re-running the pipeline.

## What it caches, and how that differs from the cache we already had

`agents/shared/athena_client.py` has had a 300 second in-process cache for a while.
That one caches `SQL -> rows`. It saves the Athena scan and nothing else: you still
pay for classification, for NL to SQL generation, and for the prose write-up. On a
raced query you pay all of that twice.

This one caches `question -> finished answer`, which is where the seconds actually
are. It sits above the SQL cache and the two do not conflict.

Redis rather than another in-process dict because the in-process ones die with the
container and are invisible to a second replica. The booth case needs state that
survives the redeploys that happen constantly during a show, and that any
orchestrator can read.

## Where it sits, which is narrower than it looks

The key is the query text plus the answering agent plus a fingerprint of the model
config. No session, no client IP. That is on purpose, because an answer that only
ever came back to the person who asked first would be pointless. But it means **a
cached entry will be served to a caller who did not populate it.**

So the cache may only be consulted from a point where the response is a function of
the query text alone. In `handle_query` that point is after every guardrail:

```
POST /query
  ├─ quarantine check (per session_id) ──────────► cover, returns
  ├─ restricted-range / zone cover filter ───────► cover, returns
  ├─ classification (LLM)
  ├─ refusal verdict (LLM) ──────────────────────► cover, returns
  ├─ athena kill-switch (admin toggle) ──────────► cover, returns
  │
  └─ CACHE LOOKUP  ◄── everything above has already returned
        ├─ hit  → paced, returned, no agent call
        └─ miss → _route_raced → agent(s) → sanitise → CACHE WRITE
```

Moving the lookup in front of those checks breaks four different things:

| Check | What caching in front of it does |
|---|---|
| Quarantine | Replays a contained session's cover to everyone, or serves a real answer to a contained session and silently defeats Manifold containment |
| Restricted range | Freezes whichever way the filter happened to fall |
| Refusal | The verdict is an LLM call and is not deterministic for a fixed string, so a cache pins one roll of the classifier for the whole TTL |
| Kill-switch | An operator flips it mid-incident and cached answers keep flowing past it |

`tests/python/test_response_cache.py::TestCoverResponsesAreNeverCached` asserts the
source order of `handle_query` for exactly this reason. If someone reorders the
function, that is what should go red.

The write-back happens after `sanitize_output_text` / `sanitize_output_obj`, not
before. Storing pre-sanitisation text would keep leaking under old redaction rules
until every entry aged out, which is the same reason `athena_client` stores rows
post-ipscope-filter.

## Why a hit is deliberately slow

A hit that returns in two milliseconds next to a live answer that takes eight
seconds makes response time a side channel. An observer who can tell "cached" from
"computed" can tell which questions have been asked before. Apply the same reasoning
to a cover response and it becomes a guardrail oracle: fast means filtered.

So a hit is padded to a plausible total wall-clock drawn uniformly from
`[RESPONSE_CACHE_HIT_DELAY_MIN, RESPONSE_CACHE_HIT_DELAY_MAX]`, 2 to 5 seconds by
default. Uniform rather than fixed because a constant 3.000s on every hit is a tell
of its own, and two byte-identical response times are the pattern that gives a cache
away. The `ATHENA_CACHE_HIT_DELAY_SECONDS` knob in `athena_client.py` is the same
idea one layer down.

Two details worth knowing:

* It is a **target total**, not an added delay. The padding subtracts whatever the
  request has already spent, so a hit lands at 2 to 5 seconds from the caller's
  point of view rather than 2 to 5 seconds on top of classification.
* A hit that is already slower than the target is not padded further. The tell being
  guarded against is answers arriving too early.

The sleep is `asyncio.sleep`, so concurrent requests keep being served while one
waits.

## Cache hits carry no lane metadata

No race happened on a hit, so there is no honest second opinion to swap to.
`_route_cached` returns without `_lane`, the orchestrator suppresses the lane block,
and the UI shows no `⇄` button. A swap control whose timings were invented would be
worse than no swap control.

The model config is part of the key (`_lane_fingerprint()`), so repointing the local
lane at a different GGUF misses rather than serving an answer attributed to a model
this box no longer runs.

## Failure behaviour

Every operation swallows its own exceptions and reports a miss. Redis down, slow,
full or misconfigured degrades this to "no cache" and never to "no answers". Ops are
wrapped in a 0.75s timeout, retries are off, and the `redis` package itself is
optional at import: a box without it runs uncached rather than failing to boot.

Errors are never stored. Caching one unreachable-agent blip would turn it into
fifteen minutes of them, so `_store_answer` drops anything with
`agent_used == "error"` or a blank answer.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `RESPONSE_CACHE_ENABLED` | `true` | `false` short-circuits every op without touching Redis |
| `REDIS_URL` | `redis://redis:6379/0` | Compose service name; port is `expose:` only |
| `RESPONSE_CACHE_TTL_SECONDS` | `900` | Shorten it for a show where freshness beats hit rate |
| `RESPONSE_CACHE_HIT_DELAY_MIN` | `2.0` | Set both to `0` to disable pacing (do not, in front of an audience) |
| `RESPONSE_CACHE_HIT_DELAY_MAX` | `5.0` | |

The Redis container runs with `--maxmemory 256mb --maxmemory-policy allkeys-lru`, no
AOF and no RDB. Nothing in here is worth persisting: on a cold start the cache is
empty and every question is simply a miss.

## Admin surface

Both routes are on the orchestrator behind the same bearer token as
`/admin/killswitch`, and the orchestrator port is internal only.

```bash
# state: connected, entry count, ping, TTL, delay window (credentials masked)
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" http://orchestrator:8001/admin/cache

# drop every entry (SCAN over our prefix, not FLUSHDB)
curl -s -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" http://orchestrator:8001/admin/cache
```

Purge after a data-lake backfill, after tightening a redaction rule, or when a demo
answer has gone stale on stage.

## Watching it work

Hit rate is the only signal, because a hit is paced to look like a live answer and
so latency graphs will not show it. Two counters on the orchestrator meter:

* `bhnoc.orchestrator.cache_hits`
* `bhnoc.orchestrator.cache_misses`

Both tagged with `agent.used`. Spans also carry `cache.hit` and, on a hit,
`cache.pad_seconds`.

## Tests

`tests/python/test_response_cache.py`, 54 cases. A hand-rolled fake async client
rather than `fakeredis`, which keeps the suite installable with no new test
dependency and still exercises real JSON serialisation, TTL and key derivation. What
it does not cover is genuine Redis semantics, so the TTL test asserts on the argument
handed to the driver rather than on expiry actually happening.
