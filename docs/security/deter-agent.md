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
| latency | one real LLM call | one real LLM call |

`agent_used` is the one that matters most: it reaches the browser, and a caller
whose agent changes the turn after a probe has been told exactly what they needed
to know. `data` is null because the deter agent's payload names the facets it
read, and forwarding that would describe the mechanism to the person it is aimed
at. The real accounting lives on the span (`deter.served`, `deter.screen_reason`,
`deter.fallback_reason`) and in the `bhnoc.deter.*` metrics, which are admin-side
only.

Latency is where this beats the canned cover outright: a cover returns instantly,
while every genuine answer takes an LLM round trip. A deter answer takes the same
round trip because it *is* one.

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
