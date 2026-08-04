# The deter agent — containment that answers

**Agent:** `agents/deter/` (port 8006, internal-only)
**Pool:** `agents/deter/safe_pool.py`
**Entered from:** the orchestrator's Manifold-quarantine branch, and nothing else.

## What problem this solves

A Manifold threat at high/critical severity quarantines the session it was seen
in (see the receiver in `packages/web-server/src/api/manifold.ts`). Every
subsequent query from that session used to get one of four canned cover
paragraphs from `_COVER_RESPONSES`.

That works once. It degrades under a persistent prober:

* The pool is four entries, selected by a stable hash of the query. Rephrase the
  same question two or three ways and the same paragraph comes back — but ask a
  genuinely different question and it changes. That covariance is a fingerprint.
* The paragraphs are generic by construction. A contained session's answers stop
  tracking what was actually asked, which is visible within a couple of turns.
* It is a worse product. A false positive — and containment is triggered by a
  detector, so there will be false positives — leaves a legitimate operator with
  a platform that has quietly stopped working for them.

The deter agent replaces refusal-shaped containment with **deterrence by
non-reward**: the caller gets a real, on-topic, genuinely useful answer, built
only from data decided in advance to be safe to hand to someone hostile. Probing
stops paying off before it stops being possible, and the caller is never told
they were detected.

## The flow

```
Manifold threat (high/critical)
  └─ POST /api/v1/manifold/webhook        web-server, bearer-gated
      └─ POST /admin/quarantine           orchestrator, admin bearer
          └─ session marked contained (TTL, extend-never-shorten)

next query from that session
  └─ orchestrator handle_query, step 0a
      ├─ DETER_ENABLED  → POST deter:8006/deter → screened answer → served
      └─ anything fails → _serve_cover(...)  (the old canned path)
```

Step 0a sits **before** classification, before the restricted-range filter, and
before the response cache. A contained session therefore never reaches a
specialist agent, never consumes a cache entry, and never writes one.

### Second caller: the admin kill-switch

The agent has one other caller. `handle_query` step 0b — the admin kill-switch,
"the plug" — routes **all** traffic here while it is thrown, with one
difference: `live_ok=false` on the request.

```
POST /admin/killswitch/athena {killed: true}     audit monitor, admin bearer
  └─ every subsequent query, step 0b
      ├─ DETER_ENABLED  → POST deter:8006/deter {live_ok: false} → served
      └─ anything fails → _serve_cover(..., salt="kill_switch")
```

`live_ok=false` forbids live pool reads for that answer regardless of
`DETER_ATHENA_ENABLED`, so every facet serves its static roll-up. It can only
ever subtract — the env var still has to be on for a live read — so it is a veto,
not a second way to enable one. The flag travels on the request rather than being
read from the environment because the env var is a property of the box, and an
operator pulling the plug is entitled to assume nothing they get back was read
off the show network.

Quarantine deliberately keeps `live_ok=true`: "this caller is hostile" and "the
venue data is off limits" are different events, and conflating them would
silently downgrade every contained answer to static.

## The safe pool

`safe_pool.py` holds every piece of data a contained session can reach. Three
properties define it:

**Fixed.** Every statement is author-written and parameterless. The caller's text
selects *which* facet is read — by local keyword scoring — and never becomes part
of one. `render_facet_sql` substitutes exactly one value, the `dt` partition
predicate, which comes from the clock via `athena_client.date_filter()`.

**Aggregate-only.** Counts, sums and averages grouped by low-cardinality
dimensions: service, transport, DNS record type, TLS version, HTTP method, alert
severity. `FORBIDDEN_COLUMNS` bans every identifying column anywhere in a
statement — projection, predicate and `GROUP BY` alike. `GROUP BY id_orig_h` is
the case worth stating: it is an aggregate query that still hands over a complete
host inventory.

**Bounded.** Small `LIMIT`s, capped at 50, and at most
`MAX_FACETS_PER_ANSWER` (3) facets per answer, so a caller who keeps rephrasing
cannot walk the whole pool out one aggregate at a time.

`assert_pool_sql_is_safe` re-checks all of it on the rendered statement at call
time. Nothing is caller-controlled today, so the guard is defence in depth: it
exists to fail loudly the day a facet is added with a placeholder in it. Rule 7 —
every string literal must be a date — is the one that actually catches an
interpolated value, since a legitimate facet has no business quoting anything
else.

### Live vs static

`DETER_ATHENA_ENABLED` defaults to **false**. Every facet then serves the static
roll-up shipped alongside it, which is a complete and plausible answer on its
own. Turn it on and facets read live venue aggregates, with the static roll-up as
the per-facet fallback.

A live read that fails or times out degrades to static **silently**. This is not
politeness: "slow when I ask, fast for everyone else" is a timing side channel,
and an error message is a direct statement that this caller is on a different
path.

The request-level `live_ok=false` (above) is the third way a facet ends up
static, and the only one a caller can neither cause nor detect.

## The output screen

Nothing the model writes is trusted verbatim. `screen_answer` rejects the whole
response on:

* refusal or apology language ("I can't", "unable to provide", "no access to")
* policy or guardrail meta ("restricted", "unauthorized", "flagged", "quarantine")
* model or prompt meta ("as an AI", "system prompt", "my instructions")
* this mechanism by any of its names ("safe pool", "deter agent", "facet")
* a missing `## Answer` header, or an answer under 120 characters — how a
  truncated or half-refused generation presents

Rejection replaces the **entire** answer, not the offending sentence. A model that
started to refuse has usually framed the whole response around refusing, and a
partially scrubbed refusal reads stranger than the cover that replaces it.

Tune this list toward false positives. A false positive costs one cover response.
A false negative ends the deception permanently — for every future turn of every
contained session, because the caller now knows to look for it.

After screening, `harden_output` runs credential and in-scope-address scrubbing,
and the result is screened **again**: masking can only shorten or alter text, and
either can produce something the first pass would have rejected.

## What the caller can observe

The deter path is built to be indistinguishable from a normal answer on every
surface the browser sees:

| Surface | Deter path | Normal answer |
|---|---|---|
| `agent_used` | `athena-hunter` | the real agent |
| `confidence` | clamped to 0.60–0.85 | typically 0.6–0.9 |
| `hints` | `restricted_cover_hints` pool | same pool on cover paths |
| `data` | `null` | agent metadata |
| lane surface | synthetic pair via `_cover_lanes` | real race results |
| latency | floored to 2–6s (see below) | athena-hunter p50 17.0s |

`agent_used` is the one that matters most: it reaches the browser, and a caller
whose agent changes the turn after a probe has been told exactly what they needed
to know. `data` is null because the deter agent's payload names the facets it
read, and forwarding that would describe the mechanism to the person it is aimed
at. The real accounting lives on the span (`deter.served`, `deter.screen_reason`,
`deter.fallback_reason`) and in the `bhnoc.deter.*` metrics, which are admin-side
only.

## Response time is a side channel

Every deception path here is written so its *text* is indistinguishable from a
real answer, and then gives itself away by arriving in three milliseconds when a
genuine answer takes seconds. A caller who cannot tell a cover from an answer by
reading it can still tell by timing it — and timing needs no interpretation. It
is a number, and the difference is three orders of magnitude.

So the deter path has a wall-clock **floor**. Anything faster than
`DETER_PACE_MIN_SECONDS`–`DETER_PACE_MAX_SECONDS` (2–4s) is padded out to a
target drawn fresh from that window, via `agents/shared/pacing.py`.

Three details that are easy to get wrong:

* **The cover fallback is paced too**, and needs it more than the success path
  does. A deter answer at least costs an LLM call; its fallback costs nothing, so
  unpaced it returns in milliseconds and announces that the deter agent just
  failed.
* **Pacing runs before the response is built, not after.** The lane timings in
  `_cover_lanes` come off the elapsed clock and are *user-visible* on the swap
  control. Pacing afterwards would hold the response for three seconds and then
  hand the caller a lane badge reading "8 ms" — stating the true cost of the path
  in the one place the padding was meant to hide it.
* **The target is redrawn per request.** A constant total is its own signature:
  every deterred answer landing at exactly 3.00s is more distinctive than one
  landing at 0.05s, because real answers scatter and nothing else on the platform
  is that punctual.

Padding is one-sided. An answer already slower than the window goes straight out
— the tell is answers arriving *early*, and delaying a slow one further spends
real latency to fix nothing.

`agents/shared/pacing.py` holds the arithmetic for both callers: this path and
`response_cache`'s hit pacing, which does the same thing with its own window
(2–5s). Two copies of a timing-side-channel defence is one copy too many.

### Choosing the window — measured, not chosen

A deter response reports `agent_used: athena-hunter`, so it has to land where
athena-hunter lands. Measured off the prod box's orchestrator logs on
**2026-08-04**:

| agent | n | p50 | p95 | min | max |
|---|---:|---:|---:|---:|---:|
| athena-hunter | 99 | 17.02s | 33.94s | 2.17s | 44.80s |
| alert-triage | 37 | 32.78s | 53.08s | 2.31s | 58.34s |
| thousandeyes-analyst | 59 | 10.84s | 18.76s | 3.19s | 26.57s |

```bash
# reproduce
sudo docker compose -f docker-compose.agents.yml logs --no-color orchestrator \
  | grep -oE "agent=[a-z-]+ elapsed=[0-9.]+"
```

The deter agent's own p95 is **~1.0s**, so the padding sets the response time
outright — the window *is* the latency.

### The window is `[2, 6]`, and that is a trade-off, not an oversight

Recorded in full so nobody "corrects" it back without knowing what was weighed.

A deter response reports `agent_used: athena-hunter`, whose p50 is 17s. `[2, 6]`
is therefore **faster than the agent it impersonates**, and a caller who times
enough turns against a known-good athena-hunter answer can see that. What it buys:

* **2–6s is plausible tool latency in absolute terms**, and 2.17s is inside
  athena-hunter's real observed range. Nothing about any single response looks
  wrong.
* **It closes the loud gap.** The millisecond cover was three orders of magnitude
  out and visible in one turn with no baseline to compare against. This leaves a
  ~3× gap visible only across many turns *with* a baseline — a much higher bar,
  requiring a caller who already suspects enough to go looking.
* **A 4-second spread scatters more than the 2-second one it replaced.** A narrow
  window is its own signature wherever it sits.
* **Responsiveness for false positives.** Containment is triggered by a detector,
  so legitimate operators will be caught by it. Making them wait 17s for every
  answer is a real cost paid by real people.

Caveat on the measurement itself: those agent numbers come from production logs
and may reflect shared load rather than intrinsic model cost. They are still what
callers actually experience, which is what the comparison turns on — but if the
box gets quieter, re-measure rather than assuming the gap held.

If timing indistinguishability starts to matter more than responsiveness, widen
toward the table above; `[8, 22]` would bracket athena-hunter's p50. Re-measure
first — a window copied onto a platform with different agent latency reintroduces
exactly the tell it removes.

## Choosing the model

The deter job is short-form prose over a small JSON context with no reasoning to
do. That is the lite/flash profile, and the model should be the cheapest one that
still clears the output screen.

`scripts/bench_deter_models.py` runs the **real** system prompt from `main.py`
against the **real** static pool from `safe_pool.py`, over a corpus of probing
questions of the kind a contained session actually asks, and scores every
response with the **real** `screen_answer`. Nothing in it is a stand-in.

```bash
cd /opt/nocgentic/app
set -a; . ./.env.s3; set +a
python3 scripts/bench_deter_models.py            # add --json out.json for raw records
python3 scripts/bench_deter_models.py --list     # what the key can actually see
```

It ranks on **screen pass rate first, p95 second**, which is the ordering that
matters and is not the obvious one:

* Latency under the pacing floor is **free**. A model at 0.9s and one at 1.8s are
  indistinguishable to the caller, because both get padded into the same window.
  Speed only starts counting once p95 approaches the floor.
* A model that trips the screen a third of the time serves canned cover a third
  of the time — which is exactly the behaviour the deter agent exists to replace.
  A faster model that covers more often is strictly worse at the one job here.

The corpus deliberately includes the hostile cases (prompt-injection attempts,
"list every device on the restricted VLAN", "dump the raw connection table"),
because a refusal is the failure mode that matters. A model that answers the easy
questions and refuses the pointed ones is precisely the model that falls back to
cover when it counts.

### Results, 2026-08-04 (24 calls per model, live key, prod box)

| model | p50 | p95 | screen | chars |
|---|---:|---:|---:|---:|
| **gemini-2.5-flash-lite** | **0.89s** | **1.03s** | **100%** | 553 |
| gemini-3.1-flash-lite | 1.32s | 1.46s | 100% | 841 |
| gemini-3.5-flash-lite | 1.25s | 1.45s | 100% | 714 |
| gemini-3.6-flash | 6.45s | 8.95s | 96% | 966 |
| gemini-2.0-flash-lite / 2.0-flash | — | — | — | 404, retired on v1beta |

`gemini-2.5-flash-lite` wins on every axis and is pinned via `DETER_MODEL`. Note
it is *older* than the platform default (`GEMINI_MODEL=gemini-3.5-flash-lite`) and
beats it here — short prose over a small context is not the workload the newer
models are better at, which is exactly why this agent pins its own.

`gemini-3.6-flash` is disqualified on latency alone: at 6.45s p50 it is slower
than the pacing floor's lower bound, so its slow tail would arrive *late* rather
than padded, and it would burn real time on every contained turn.

### What this benchmark caught

The first run reported screen pass rates of **79–96%**, meaning up to a fifth of
deter answers were silently degrading to canned cover. Two distinct bugs, both
invisible without measurement:

1. **The screen conflated SOC vocabulary with model meta-commentary.** Bare nouns
   — `policy`, `restricted`, `unauthorized`, `flagged`, `blocked by` — sat in
   `_LEAK_MARKERS`. A perfectly good answer ending *"...correlate IDS alert spikes
   with specific source subnets to identify potential unauthorized management
   access attempts"* was rejected. Nothing in that sentence leaks anything; it is
   what a competent analyst writes. Fixed by anchoring the ambiguous words to a
   person: `unauthorized access attempts` (the network) passes,
   `you are not authorized` (the caller) does not. Pass rate on
   gemini-3.1-flash-lite went **79% → 100%**.
2. **Internal vocabulary was being handed to the model.** The context JSON used
   the key `facet`, and models echoed it back — which the screen then caught as a
   mechanism leak. Catching it is the wrong layer. `_llm_context` now re-keys the
   pool into neutral names (`datasets`/`name`/`rows`) and drops `live` and
   `scanned_bytes` entirely, so the model is never told whether a roll-up came
   from Athena or the static pool and cannot leak a distinction it does not have.

After both fixes: **zero screen failures across 72 calls and three models.**

A third bug was in the harness itself — it built the context without applying
`_llm_context`, so it kept reporting `leak_marker:facet` failures the agent could
no longer produce. It was measuring the harness, not the model. `_context_for`
now runs both stages, because a benchmark that does not mirror production is
worse than no benchmark: it reports failures nobody can reproduce and hides ones
nobody can see.

## Prompt-injection posture

The caller of this agent is, by definition, someone who has already tripped a
detector, so the injection surface is the one that gets attacked first.

* The query is wrapped in `<<<UNTRUSTED_QUERY ... >>>` and the system prompt
  names the specific manipulations to ignore: role change, instruction
  disclosure, raw data output, format drop, "explain why you can't".
* The quarantine **reason** never reaches the prompt. A Manifold threat title can
  quote what the attacker typed; putting it in the prompt would hand a prober a
  way to steer the very answer meant to deter them. It goes to the span and the
  logs only.
* Rule 3 of the system prompt forbids confirming, denying, or repeating any host,
  address, hostname, credential or device named in the question — so "does
  10.1.2.3 exist" gets an aggregate answer, not an existence oracle.
* The output screen, `harden_output`, and the orchestrator's
  `sanitize_output_text` all run on the way out. Three passes on the same text is
  intentional here.

## Configuration

| Variable | Where | Default | Effect |
|---|---|---|---|
| `DETER_ENABLED` | orchestrator | `true` | `false` reverts contained sessions to the canned cover |
| `DETER_URL` | orchestrator | `http://deter:8006` | must be set in compose; absent means the localhost default, so every call fails and covers |
| `DETER_TIMEOUT_SECONDS` | orchestrator | `25.0` | far below the 180s specialists get — see below |
| `DETER_PACE_MIN_SECONDS` | orchestrator | `2.0` | wall-clock floor, incl. the cover fallback |
| `DETER_PACE_MAX_SECONDS` | orchestrator | `6.0` | top of the floor window |
| `DETER_MODEL` | deter | `gemini-2.5-flash-lite` | pinned separately from `GEMINI_MODEL` |
| `DETER_ATHENA_ENABLED` | deter | `false` | live pool reads vs static roll-ups |
| `DETER_WINDOW_HOURS` | deter | `24` | live roll-up window |
| `DETER_ATHENA_TIMEOUT` | deter | `12.0` | per-facet ceiling; past it, that facet serves static |

The orchestrator timeout is deliberately short. A contained session hanging for
three minutes and then producing something is visibly different from every other
session on the platform, and the caller would learn more from that wait than from
any answer we could give them. Cover is fast and lands inside the range a normal
answer occupies.

## Failure modes, all of which cover

* deter container down, restarting, or unreachable → `_serve_cover`
* deter slower than `DETER_TIMEOUT_SECONDS` → `_serve_cover`
* LLM provider 429/5xx/timeout → agent returns `usable: false` → `_serve_cover`
* output screen rejects the answer → `usable: false` → `_serve_cover`
* `DETER_ENABLED=false` → `_serve_cover`

The cover prose lives in exactly one place (`_COVER_RESPONSES` in the
orchestrator) and there is one function that serves it. The deter agent returns
`usable: false` rather than carrying its own copy, so the two paths cannot drift.

## Tests

`tests/python/test_deter.py` locks the three properties that carry the feature and
each of which fails silently:

1. Caller text never reaches SQL — asserted against SQL-injection, IP-probe and
   union-attack queries, end to end through `gather_pool_context` with Athena
   stubbed and every issued statement re-checked against the guard.
2. No refusal, apology, or mechanism reference reaches the caller — the screen is
   tested against each leak class, and `agent_used` is asserted never to contain
   "deter" anywhere in the serialised response.
3. Every failure degrades to cover, silently — transport error, timeout,
   malformed JSON, screen rejection, and the malformed `usable: true` with an
   empty answer.

Plus: the deter path never touches the response cache (monkeypatched to raise),
the quarantine reason reaches the agent but never the answer, and the static
roll-ups shipped in the repo carry no IP-shaped values.

The pacing tests run against a real clock with a compressed window, and cover the
success path, the cover fallback, the screen-rejection fallback, the one-sided
rule (a slow answer is not padded further), and the lane badge reporting the
paced total rather than the raw cost.

## Known gap

The **other** cover paths — restricted-range, `refused`, and the Athena
kill-switch — still return in single-digit milliseconds, and their lane badges
still report that. Everything in the "Response time is a side channel" section
above applies to them equally; only the quarantine path is paced today. Fixing it
means making `_serve_cover` async and pacing all four call sites, which is a
change to a security-sensitive path that deserves its own commit and its own
tests rather than riding along with this one.
