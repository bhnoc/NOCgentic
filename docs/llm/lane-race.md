# Lane race: cloud vs local, side by side

Two provider stacks answer the same query **concurrently**. The first to finish is
what the analyst sees; a swap control in the answer bubble reads the other one.

| lane | NL→SQL | prose (analyst-facing text) |
|------|--------|------------------------------|
| `cloud` | Gemini (`GEMINI_MODEL`) | Gemini |
| `local` | **AQLight** (`LOCAL_SQL_MODEL`) | **AQLight** (`LOCAL_PROSE_MODEL`, falls back to the SQL model) |

## The local lane is one model by default

The lane is addressed by **role** (`role="sqlgen"` vs `role="prose"`), so it *can*
serve the two jobs from two models. By default it does not: `LOCAL_PROSE_BASE_URL`
and `LOCAL_PROSE_MODEL` fall back to the `LOCAL_SQL_*` pair, so AQLight answers both.

That is a deliberate reversal. The design originally required a second model. The
2026-07-30 capability eval
([`qa/AQLight-capability-sweep.md`](../../qa/AQLight-capability-sweep.md)) scored
AQLight excellent at NL→SQL (0.962) and poor at free-text synthesis (relevance 0.464
against Gemini's 0.718), so the fallback was forbidden outright to keep prose from
silently reaching the SQL specialist. The 2026-08-04 bench (28 deterministic cases,
real prompts) does not back treating that as disqualifying:

| local configuration | mean accuracy | wall-clock |
|---|---|---|
| Foundation-Sec everything | 97.4% | 18.7s |
| AQLight SQL + Foundation-Sec prose | 95.8% | 13.4s |
| **AQLight everything** *(default)* | **93.0%** | **14.6s** |

A ~3-point gap, not a categorical failure. And AQLight is the only local model
running as a durable service (`aqlight.service`, `Restart=always`), so requiring a
second GGUF left most boxes with no local lane at all. That is worse than a slightly
weaker one.

**Foundation-Sec is still the better model at *both* roles** (SQL 97.5% against
92.5%, prose 94.8% against 86.5%). If you are willing to run a second server, point
`LOCAL_SQL_*` and `LOCAL_PROSE_*` at it rather than splitting the roles.

`resolve_lane()` in `agents/shared/llm_client.py` is what routes each call.

## Serving a second model (optional)

One `llama-server` process serves **one** GGUF, so a two-model lane needs two ports.
AQLight already runs as `aqlight.service` on 8080 (see
[`AQLight-integration.md`](AQLight-integration.md)); a prose model needs its own unit
on 8081.

Use the **Instruct** variant. `fdtn-ai/Foundation-Sec-8B` is a base,
completion-only model and will not follow the JSON-fence and format instructions
these prompts rely on.

```bash
# Foundation-Sec-8B-Instruct on 8081 (mirror aqlight.service; Restart=always, bind 0.0.0.0)
~/llama.cpp/build/bin/llama-server \
  -m ~/models/foundation-sec-8b-instruct-q4_k_m.gguf \
  --host 0.0.0.0 --port 8081 -ngl 99 -c 8192 --alias Foundation-Sec &

curl -sf http://127.0.0.1:8081/health    # {"status":"ok"}
```

Both MUST bind `0.0.0.0`, not `127.0.0.1`: the agents reach them from inside Docker
via the bridge gateway.

Budget the VRAM: two 8B q4 models are ~9.8GB resident, which fits a 15GB T4 but
leaves little headroom.

## Enabling

In `.env.s3` on the box:

```bash
LANE_RACE=auto                                            # default
LOCAL_SQL_BASE_URL=http://host.docker.internal:8080/v1    # AQLight
LOCAL_SQL_MODEL=AQLight
# Optional. Omit these and AQLight writes the prose too:
# LOCAL_PROSE_BASE_URL=http://host.docker.internal:8081/v1
# LOCAL_PROSE_MODEL=Foundation-Sec
```

Then recreate the agents. `auto` races only when a local endpoint is set, so the same
image runs single-lane on a CPU-only box with zero failed calls. Use `LANE_RACE=on`
to force racing (a misconfigured box then fails loudly instead of quietly serving one
lane) and `off` to disable it entirely.

`local_lane_available()` reads the **raw** env for this decision, not the resolved
URLs: `LOCAL_LLM_BASE_URL` itself defaults to a non-empty `http://localhost:8080/v1`,
so checking the resolved value would report a local lane on every box and `auto`
would race a CPU-only box against a server that is not running.

## A note on the hardware premise

The race assumes local is *sometimes* faster. On the current box, a `g4dn.xlarge` /
Tesla T4 and **not** the 46GB L40S the older docs describe, it is not: local sustains
~25 tok/s against Gemini's ~194, and the cloud lane wins on accuracy too (100.0% /
8.7s vs the local best of 97.4% / 18.7s). The plumbing is correct; the hardware
assumption under it is stale. On a T4, expect the swap button to show a slower and
weaker answer. Re-measure before claiming otherwise on a bigger GPU.

## Behaviour worth knowing

**Both lanes run the full pipeline.** Separate classify, separate NL→SQL, separate
Athena execution. That makes the latency comparison honest and it also means **each
lane bills its own Athena scan**, so a raced query costs roughly double in
bytes-scanned. Set `LANE_RACE=off` if that matters more than the demo.

**First *success* wins, not first completion.** A local lane whose llama-server is
down fails in about a millisecond. If that counted as winning, every query on a
degraded box would return an error while a good cloud answer was still in flight.

**The loser is not cancelled.** It keeps running and files itself into the
orchestrator's lane store, which is what the swap control reads via
`GET /lanes/{job_id}` (the web-server polls it, same pattern as async hints). The
cost is one extra in-flight pipeline per raced query; cancelling it would leave the
swap button with nothing to swap to.

**A dead lane is not a dead query.** If one lane errors, the other answers and the
swap simply doesn't appear. Leaving the race on while the GPU box reboots is safe.

**Classification is a barrier, not part of the race.** Both lanes classify
concurrently (~500 ms), then reconcile before any agent is touched:

- **Fail closed on `refused`.** If *either* lane flags the query, both serve cover.
  A local model that is worse at spotting prompt injection must not be able to
  unblock what the cloud lane refused, and the swap must not become a way to read
  a withheld answer.
- **One agent for both lanes.** Otherwise the swap compares two different agents'
  findings rather than two models' writing, and means nothing.
- Ties go to cloud, which has the better routing eval.

**Cover paths expose two lanes too.** If the swap control appeared only on genuine
answers, its presence or absence would tell a caller whether a query was
filtered, turning a UI affordance into a guardrail oracle. Guardrail, quarantine
and kill-switch covers therefore emit the same lane pair (no LLM is called; both
lanes carry the same author-written text, with non-identical latencies since two
byte-identical elapsed times would themselves be a tell).

**The loser is sanitised separately.** It lands after the response has been sent,
so it never passes through `handle_query`'s output sanitiser. `_record_lane_result`
applies `sanitize_output_text` / `sanitize_output_obj` itself. Without that, the
deception layer would hold on the answer shown first and leak restricted IPs on the
one behind the swap button.

## UI

The answer bubble grows a lane bar: which model answered, its elapsed time, a
`FASTEST` badge on the winner, and a `⇄` swap button. Swapping re-renders the
answer, confidence, per-lane metrics and raw data from client-side state, with no
refetch. The default is always the fastest lane, and a late-arriving second lane
lights up the button **without** replacing what the reader is already looking at.

The hints row sits outside the swappable region on purpose: hints arrive
asynchronously, so a swap after they land would otherwise wipe them.

## Env reference

| var | default | meaning |
|-----|---------|---------|
| `LANE_RACE` | `auto` | `auto` (race iff local lane is configured) \| `on` \| `off` |
| `LOCAL_SQL_BASE_URL` | `LOCAL_LLM_BASE_URL` | AQLight's llama-server (NL→SQL) |
| `LOCAL_SQL_MODEL` | `LOCAL_LLM_MODEL` | served alias for the SQL model |
| `LOCAL_PROSE_BASE_URL` | `LOCAL_SQL_BASE_URL` | prose llama-server; unset = same server as SQL |
| `LOCAL_PROSE_MODEL` | `LOCAL_SQL_MODEL` | served alias for the prose model |

Tests: `tests/python/test_lane_race.py` (race semantics, fail-closed classify,
cover-lane parity, metrics isolation), `packages/web-server/test/lanes.test.ts`
(lane polling), and `tests/ui/lane-swap.mjs`, a headless-Chrome gate that clicks the
real `⇄` button (`bash tests/ui/run.sh`). The stub answers any query
containing "lane race" with the winner first and the pair on its second poll, so
the pending state and the late-arriving lane are both exercised rather than
assumed.
