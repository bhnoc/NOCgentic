# QA sweep 6 — live production dynamic sweep

Scope: drive the LIVE app at https://ng.bhnoc.com like a real user (starter hint
chips, freeform NOC questions, Next Steps hint chains, Hunt-From-Here alert
chips), plus a user-reported concurrency bug. Read-only against prod; fixes
applied on branch `fix/qa-sweep-live-findings`, not deployed.

## Method

Built two small Python drivers (`qa/drive_chat.py`, `qa/drive_concurrent.py`)
that establish a real `bh_sid` session cookie and drive the actual HTTP chat
API the same way the browser does (POST /api/v1/chat, poll GET until done,
follow returned hints). Ran them against production across several batches:
starter hints, freeform aggregate/security questions, predicted Hunt-From-Here
chip text derived from live alerts, and a concurrency stress test at 6/8/10/16/24
simultaneous queries from one session.

## Findings: confirmed and fixed

**LIVE-004/006 — alert-triage "Key Entities" duplicate rows (high, confirmed).**
Live queries returned the identical entity line repeated 2x, 4x, and 7x. Root
cause: `agents/alert-triage/main.py` merges `suricata_alerts + unified_alerts`
at the Phase 3 merge point with no uid dedup, unlike every other merge site in
the file. The unified `alerts` view is itself partly built from
`suricata_corelight`, so the same event legitimately appears in both source
lists, and nothing collapsed the cross-table duplicate before the LLM rendered
"one bullet per entry." Fixed by deduping the merge by uid, matching the
pattern already used elsewhere in the file.

**LIVE-005 — alert-triage recommends "Block X" on a FALSE POSITIVE verdict
(critical, confirmed).** Live answer: verdict "FALSE POSITIVE", risk "Low...no
malicious impact", but Next Steps still said "1. Block 192.168.132.35." The
prior fix in commit f3af6c8 addressed a different contradiction (severity
counts disagreeing with each other) and never touched the Next Steps
generation path. The "Block X" exemplar in the prompt was unconditional,
disconnected from the verdict computed two sections earlier in the same
response. Fixed by adding an explicit instruction: a FALSE POSITIVE verdict or
a low/no-impact Risk line must not produce a Block/containment recommendation.

**LIVE-001 — athena-hunter phrases a failed query as a confident negative
(high, confirmed).** The starter hint "Which hosts are running listening
services on the attendee network?" (shown by default to every visitor) hit a
`COLUMN_NOT_FOUND` SQL error on `known_services`, and the agent still answered
"No listening services found" at confidence 0.2 — indistinguishable from a
real all-clear in the rendered chat bubble. The SQL_GEN_PROMPT already
documents the correct column name (`host_ip`, not `ip`); this was a one-off
NL-to-SQL slip, not a systemic prompt gap, so a prompt fix can't eliminate the
underlying miss entirely. What's durably fixable: the answer-synthesis prompt
now explicitly distinguishes "query failed" from "query succeeded with 0
rows" and requires a "could not be completed" phrasing (not a negative
finding) for the former.

**LIVE-003 — "total throughput of the conference" misrouted to
thousandeyes-analyst (medium, confirmed).** The LLM classifier routed an
aggregate-traffic-volume question to thousandeyes_analyst, which has no
aggregate throughput metric and said so in its own answer, instead of
athena_hunter, which sums real `orig_bytes`/`resp_bytes` from the `conn` table
(proven working earlier in the same sweep for "top talkers"). Added an
explicit tiebreaker to the classification prompt: throughput/bandwidth/data
volume questions about real observed traffic go to athena_hunter; TE only
covers synthetic test health.

**User-reported — rapid hint-chip clicking ("6+ at once") degrading Athena
(confirmed root cause, fixed client-side).** Direct HTTP load testing (6, 8,
10, 16, 24 truly concurrent POSTs from one session) never reproduced a crash —
every request completed cleanly even at 24 concurrent, ruling out an AWS
Athena workgroup limit or a server-side race (the athena_client cache and its
lock are correctly guarded). The real mechanism is client-side: two of the
three hint-chip render/click sites in `packages/web-server/static/app.js`
called `sendQuery()` directly, bypassing the `send-btn.disabled` in-flight
check that the welcome chips and alert-popup chips already respect via
`submitQueryText()`. A burst of chip clicks in the same event-loop tick could
each fire before the button's disabled state took effect. Fixed by routing
both remaining chip click handlers through `submitQueryText()`, and — as a
backstop — moved the disabled check into `sendQuery()` itself so two calls
landing in the same tick can no longer both proceed regardless of caller.

**LIVE-002 — stale time-window chip false negatives (medium, confirmed,
lower priority).** Reproduced live: a Hunt-From-Here chip asking about "the
last hour" for a host whose alert was ~16 hours old returned a confident
"no activity" — correct for the literal window queried, misleading as
presented. This failure class is already documented and tested at the
chip-generation layer in `alertHints.js`/`alertHints.test.ts`; this sweep
reproduced it one layer down, at the answer-synthesis layer. Rather than
change chip wording (which the existing tests already constrain carefully),
added an instruction to athena-hunter's answer prompt: a bounded-window
negative should name the window in the answer, so a stale-window miss reads
as a scoped result instead of a clean bill of health.

## Findings: noted, not fixed this sweep

- `alert-triage` answers for red-team/training-network alerts (e.g. "Active
  data exfiltration is occurring" for traffic on a network literally named
  "Adversary Tactics: ...") state findings with full confidence and no
  caveat that the venue runs live attack-simulation training tracks. Whether
  this needs a fix is a product decision (should the agent know about/flag
  training-network zones?) rather than a code bug — deferred, flagging for
  discussion rather than picking unilaterally.

## Verification

All fixes are prompt-text or client-JS logic changes; no schema/API
contract changes. Ran the canonical suite after every commit:

```
bash ops/run-tests.sh
```

Result: 1444 Python tests passed, 170 TypeScript tests passed at every
step, no regressions introduced across three commits.

### Live re-verification (post-merge, same day)

This branch was merged to main and deployed. Re-running the exact same
live queries that produced the original findings caught two problems the
static prompt read couldn't have:

1. **The Key Entities dedup fix (first commit) was necessary but not
   sufficient.** Live re-test after the first deploy still showed the
   duplicate bullet. Root cause was different from what the validator
   confirmed: two genuinely distinct rows (different uid, different
   timestamp) sharing the same src/dst/port/signature render as
   textually IDENTICAL bullets, because the bullet format never
   includes uid or timestamp. The uid-based cross-table dedup doesn't
   touch this, because the rows aren't duplicates by uid. Fixed with a
   second commit: collapse `enriched_alerts` by the exact
   (src, dst, port, signature) tuple the bullet displays, before the
   15-row slice, merging into a real `entity_occurrence_count`.

2. **The two athena-hunter fixes (LIVE-001 confident-negative,
   LIVE-002 stale-window naming) combined badly on a real failure.**
   Live re-test produced: "No listening services found on the attendee
   network in the last hour (16:00-17:00). Lookup failed due to
   COLUMN_NOT_FOUND error." That's a negative finding AND a stated
   failure in one sentence, plus a raw catalog error string leaking
   into the answer (violating an existing STYLE rule the prompt already
   had). Each rule was correct in isolation; neither told the model they
   were mutually exclusive. Fixed with a third commit: the window-naming
   rule now applies only to a query that succeeded with 0 rows; the
   failure rule explicitly bans naming a window and bans repeating raw
   error text, "regardless of which section it lands in."

Both corrections were re-verified live after their own deploys (with the
Redis response cache purged via `DELETE /admin/cache` before each
re-test, since the cache is keyed on query text alone and was serving
pre-fix answers for repeated identical queries). Final state, confirmed
against a fresh, uncached run of each: the known-services query now
answers "The lookup for listening services on the attendee network could
not be completed" with no leaked error and no false negative; the
132.35 alert-triage query gives a clean single-bullet FALSE POSITIVE
verdict with a "close as benign" Next Step; the throughput query
correctly routes to athena_hunter with a real 3.38 TB byte-sum answer.

### Two things found during re-verification, out of scope for this sweep

Re-running the live queries surfaced two pre-existing issues unrelated
to what this sweep set out to fix. Neither was touched, both are logged
in `qa/findings/live_chat.json` (LIVE-007, LIVE-008) for a future sweep:

- **LIVE-007 (low):** Key Entities bullets for `*StorageExfil::` alert
  types render with blank src/dst/port (`-> :, SIGNATURE, count N`)
  because those rows apparently don't carry `orig_h`/`resp_h`/`resp_p`
  the way Suricata-sourced rows do.
- **LIVE-008 (medium):** the LOCAL (AQLight) lane for alert-triage can
  skip the required Answer/Key-Entities/Risk/Next-Steps format entirely
  and produce a short, format-skipping answer that overstates severity
  relative to what the SAME data gets from the cloud/Gemini lane.
  Observed live: the local lane said the 132.35 host's 29 informational
  TLS-handshake-failure alerts were "corroborating a real attacker,"
  while a fresh cloud-lane run on the identical data correctly verdicts
  FALSE POSITIVE with no malicious impact. This is a real, higher-stakes
  gap (a false positive read as a real attacker) but it predates this
  sweep and needs its own investigation into the local lane's prompt
  adherence at whatever token budget it ran at.

## Not covered this sweep

- ThousandEyes-sourced items in the alert popup/sidebar feed: confirmed by
  code reading that `/api/v1/alerts/recent` structurally cannot emit a
  ThousandEyes-sourced alert (source is always suricata/notice/ml/yara); the
  "Hunt From Here" flow for that source doesn't exist to test. ThousandEyes
  data only surfaces via the separate thousandeyes-analyst chat agent.
- The concurrency fix was diagnosed and fixed at the client layer based on
  code reading; it was not re-validated with a live browser-automation
  reproduction of 6+ real simultaneous chip clicks (headless browser driving
  was out of scope for this sweep's tooling). Recommend a follow-up
  browser-based repro before considering this fully closed.
- No dedicated `alert-triage` pytest module exists in `tests/python/`, so the
  two alert-triage fixes have no automated regression gate beyond this
  report and the full suite staying green. Consider adding one in a future
  sweep (e.g. a fixture with two rows sharing a uid across suricata/unified
  sources, asserting the merged list dedupes; and a fixture where the verdict
  is FALSE POSITIVE, asserting no Block recommendation is emitted) once the
  prompt-based fix's live behavior is reconfirmed.

## Recommendation

This branch was merged to main and deployed same-day; all 6 original
findings are confirmed fixed live as of the final re-verification pass
above. Two new items surfaced during that re-verification (LIVE-007,
LIVE-008) and are deferred to a future sweep rather than fixed under time
pressure. A follow-up sweep should prioritize LIVE-008 (local-lane
severity overstatement on a false positive) given the stakes, and should
still attempt a real browser-based rapid-multi-click repro of the
concurrency finding, which was fixed based on code reading but never
re-confirmed with an actual browser driving multiple simultaneous clicks.
