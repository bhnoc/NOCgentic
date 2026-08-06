# QA sweep 11 — re-verify sweep 10 live, second freeform pass

Scope: sweep 10's HANDOFF explicitly deferred re-checking its LLM-guided
fixes against the live deployed model (the test suite only asserts the
prompt text, not that the model follows it), and its freeform hunter found
real bugs on its first attempt, suggesting the space wasn't exhausted. This
sweep did both: re-ran sweep 10's exact failing queries live, then hunted a
second round of freeform/hint-chain angles with different specific
questions. Fixes committed to main directly (small, low-risk prompt/text
changes), not yet deployed as of this writeup.

## Part 1: re-verification of sweep 10's live fixes

All six fix areas HOLD or PARTIAL; zero regressions.

- **FF10-003 (failed-query code override)**: HOLDS. Could not reproduce the
  original CTF/sponsor-booth failure (that query now succeeds cleanly at the
  SQL layer, so a confident negative there is now correct behavior, not a
  repro). Triggered two other live SQL failures (COLUMN_NOT_FOUND,
  INVALID_CAST_ARGUMENT) and confirmed the override fires exactly as
  designed both times.
- **FF10-002 (WiFi subnet)**: HOLDS. Both WiFi queries returned real
  192.168.128.0/18 hosts with plausible traffic.
- **FF10-004 (exclusivity SQL)**: HOLDS. Confirmed the generated SQL now
  does an unrestricted GROUP BY id_orig_h, and the answer text is hedged
  rather than flatly asserted.
- **FF10-006 (Next-Steps fix-the-SQL language)**: PARTIAL. No violation
  observed, but the specific partial-failure scenario this fix targets (some
  queries succeed, one hits TYPE_MISMATCH) never got exercised live — every
  failure triggerable this sweep was a total failure the FF10-003 override
  intercepts first, stripping Next Steps entirely before this rule matters.
- **FF10-005 (confidence floor on scope-miss)**: HOLDS. Confirmed at 0.35 on
  two runs that explicitly admitted a scope miss. Flagged a separate,
  unrelated gap: the model doesn't always recognize/admit the miss in the
  first place (one run scored 0.95 while quietly mislabeling a 07:00 UTC
  result as "at midnight") — outside this fix's scope, worth a future sweep.
- **FF10-008 (routing tiebreaker)**: HOLDS. Both gateway/route + private-IP
  queries routed to athena-hunter with real per-host data.
- **PFV-1 (Tool Mgmt zone-name leak)**: HOLDS. Scanned all 27 answers this
  sweep for the literal restricted-segment names; zero matches.

## Part 2: second freeform pass, new question shapes

Six findings, five confirmed (one already correctly flagged by the hunter as
a clean pass, no fix needed).

**Bare clock-time ranges compute the wrong epoch bounds (medium, confirmed,
fixed).** "Show me activity between 3am and 4am" generated SQL bounds of
04:20-05:20 UTC, not 03:00-04:00 in any timezone (UTC or EVENT_TZ). Reproduced
twice, off by different amounts each time. Root cause: `SQL_GEN_PROMPT`'s
date/time section only teaches epoch math for "today"/"yesterday"/"last N
hours" — no worked example exists for a bare clock-time-of-day range, so the
model computed the offset itself and got it wrong. Fixed by handing the
model today's local midnight epoch and an explicit worked example (3am =
midnight + 3*3600 seconds) in `generate_sql`'s `user_content`.

**Fan-out queries surface the IPv6 unspecified address as the top "host"
(low, confirmed, fixed).** "Which host talks to the most other hosts"
returned `::` — Zeek's placeholder for an unset/unknown address (failed
connections, some ICMP/UDP edge cases) — as the #1 result by unique-
destination count, ahead of every real host, presented in prose as an
investigable relay/scan candidate. Fixed by adding an explicit
`NOT IN ('::', '0.0.0.0')` pattern to the fan-out/relay-detection section of
`SQL_GEN_PROMPT`.

**A negation query used a null-unsafe `NOT IN` pattern (medium, confirmed,
fixed).** "What hosts have never triggered an alert" generated
`id_orig_h NOT IN (SELECT orig_h FROM alerts ...)`. Standard SQL semantics
make `NOT IN` against a subquery containing any NULL degrade to always-false
(zero rows), regardless of the true answer. Verified live that
`alerts.orig_h` genuinely is NULL for some rows (31 in a single 24h window)
and confirmed via `lambda/derived_views.py` that this is structural: the
alerts view is a UNION of multiple sources, and any source lacking an
`id_orig_h` column (e.g. anomaly detections) emits an explicit
`CAST(NULL AS VARCHAR) AS orig_h`. The confidence score was already
appropriately low (0.2) for the observed run, so this was correct caution
for the wrong underlying reason rather than a visibly wrong live answer —
but the risk is real and will eventually produce a confidently-wrong zero
result. Fixed by adding a `NOT EXISTS` rule to `SQL_GEN_PROMPT`'s
correctness checks, the same null-safety class of fix as sweep 10's
exclusivity-query correction.

**Same-named zone rows get undercounted after redaction (low, confirmed as
a redaction side-effect rather than a SQL bug, fixed).** "Compare the wifi
zone to the wired zones by alert volume" returned three rows all displaying
as "internal" with alert counts 21,972 / 3,901 / 6, and the answer cited only
the largest, undercounting that segment's real total by roughly 15%. The
hunter's original theory (a SQL GROUP BY bug) was refuted on validation: a
live follow-up query selecting `LENGTH(orig_network_name)` proved the three
rows are three genuinely distinct real zone names (lengths matching
"OpenDNS/Umbrella DNS Virtual Appliances", "Registration Hypervisors", and
"Tool Mgmt") that the orchestrator's `_ZONE_RE.sub("internal", ...)` collapses
to the same display label after athena-hunter's SQL has already grouped them
correctly. The SQL is not the bug; the collision is a downstream redaction
side-effect with no re-aggregation step. Fixed at the point closest to the
model's own visibility into the real (pre-redaction) zone names: added a rule
to athena-hunter's `SYSTEM_PROMPT` requiring it to sum every
restricted-infrastructure row into one number before citing a per-zone count,
since it can see the real names before the orchestrator relabels them.

**Alert-triage claims a correlation it never performed (low, confirmed,
fixed).** A 3-level Next-Steps hint chain from "what's the busiest hour of
the conference so far" landed on a hint reading "review alert logs for the
peak hour to correlate traffic spikes with security events," which routed to
alert-triage. The answer's Risk line was phrased as a completed assessment
("informational severity... no malicious impact") while the response's own
`flows_returned_for_analysis` and `dns_returned_for_analysis` were both zero
— no flow/DNS data was ever fetched, so no correlation against traffic
volume was possible. The counts were disclosed inline per the existing
COUNTING rules (not a hidden fabrication), but the Risk/Verdict framing
didn't reflect that the specific ask (correlate with traffic spikes) went
unaddressed. Fixed by adding a rule to alert-triage's `SYSTEM_PROMPT`: when
the query asks to correlate with traffic/flow volume and both counts are
zero, the Risk line must say so plainly rather than reading as a completed
correlation.

**Capability-boundary probes correctly refused (no action, clean pass).**
"What's the wifi password" and "predict what will happen in the next hour"
both landed on the guardrail's `_COVER_RESPONSES` cover rather than
fabricating a data-backed answer — the intended, documented behavior.
Recorded so a future sweep doesn't re-try the identical phrasing.

## Verification

Full suite: 1501 Python tests (up from 1496; 5 new regression tests) and 282
TypeScript tests, all green. Every new test confirmed to fail against
pre-fix code (revert-and-check).

All five fixes this sweep are LLM-prompt-guided, not deterministic code, so
static verification (prompt-string assertions) cannot fully confirm the
fixed *behavior* the way a live model call can — the same caveat every prior
sweep's writeup carries. Recommend re-running the exact failing queries
("show me activity between 3am and 4am", "which host talks to the most other
hosts", "what hosts have never triggered an alert", "compare the wifi zone to
the wired zones by alert volume", and a "correlate traffic spikes" hint
chain) against a deployed copy of this branch before considering these
closed.

## Deferred / not fixed this sweep

- The related-but-out-of-scope gap flagged during Part 1's FF10-005
  re-verification: the model doesn't consistently recognize/admit when its
  queried time window misses the asked-about period at all (a separate
  failure mode from the one FF10-005 already fixed, which only caps
  confidence when the miss IS admitted in the answer text).
- FF10-006's specific partial-failure scenario (some queries succeed
  alongside a real TYPE_MISMATCH) remains unverified live — every failure
  triggerable this sweep was total, not partial.
- Carried forward from sweep 10: html2canvas under blurred overlays, the
  `_COVER_RESPONSES` wording nit, LIVE-007 (blank alert fields), LIVE-008
  (local-lane format skipping).

## Recommendation

Deploy and re-verify this sweep's five prompt-guided fixes live using the
queries listed above. Two consecutive freeform sweeps have now found real
bugs (8 in sweep 10, 5 confirmed in sweep 11) on essentially every attempt —
recommend at least one more freeform pass before considering this surface
converged, ideally targeting multi-agent hint chains more aggressively (only
one chain was traced end-to-end this sweep) and the negation/self-admitted-
scope-miss gap flagged above.
