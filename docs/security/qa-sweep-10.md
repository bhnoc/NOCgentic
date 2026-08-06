# QA sweep 10 — UI (report-issue button) + freeform chat, post-sweep-9

Scope: the user asked for the next sweep to focus on the UI and free-form
chat, explicitly excluding surfaces already covered. Sweeps 1-9 (merged to
main) already drove starter chips, alert-hunt chips, the Threat Hunt UI, and
~40 freeform chat questions. Since sweep 9 merged, four things landed with
zero QA coverage: a brand-new "report issue" screenshot/note feature, an
orchestrator Next-Steps hint filter fix, a redaction fix, and a
ThousandEyes failed-fetch fix. This sweep covered those plus fresh freeform
chat angles never tried before (hint-chain following, negation/relational/
time-boundary question shapes). Fixes on `fix/qa-sweep-10-ui-and-freeform`,
not deployed.

## Method

Four hunters ran in parallel against the live app (`https://ng.bhnoc.com`)
and the repo: report-issue security/correctness, UI regression (did the new
button reintroduce sweep 7/8's fixed bugs), live re-verification of the
three post-sweep-9 fixes, and 21 fresh freeform/hint-chain queries. Two
validators then independently traced/reproduced the report-issue and
freeform findings before any fix landed.

## Findings — report-issue button (new feature, first QA pass)

All 6 confirmed, all fixed:

- **No dedicated rate limit** on `POST /api/v1/report-issue` — it shared the
  generic 120/min-for-everything bucket despite carrying up to an 8MB body
  and triggering an S3 write per call, unlike the rest of the API surface.
  Added a route-level `{ max: 5, timeWindow: '1 minute' }` override.
- **Screenshot uploaded unscrubbed.** `credscrub.scrub_secrets` only ran on
  the note text; the captured pixels (whatever was on screen, including a
  potential alert-detail popup's raw vendor `description` prose) went to S3
  with no equivalent filtering. Documented as an accepted, explicit risk next
  to the upload code — a screenshot is pixels, not scrubbable text, matching
  how every other redaction decision in this codebase is documented.
- **`referer` field asymmetry**: `report-issue.ts`'s `extractClient()` never
  populated the field `chat.ts`'s version does, leaving it silently null for
  100% of report-issue submissions despite the shared `ClientInfo` schema
  supporting it. Added the missing line.
- **Orchestrator's `view` field had no enum constraint**, unlike the
  web-server's `z.enum(['chat','hunt'])` — the internal endpoint enforced a
  weaker contract than its own client. Changed to `Literal["chat", "hunt"]`.
- **Collapsed error messaging**: every failure (400 payload-too-large, 502
  upstream, network error) showed the same "try again in a moment," which
  loops forever for an oversized-screenshot 400 that a retry can never fix.
  Added a specific 400 path that retries once without the screenshot.
- Two lower-severity/deferred items: html2canvas's interaction with blurred
  overlapping overlays (alert-modal, hunt end-dialog) wasn't independently
  verified this sweep (deferred — html2canvas silently mis-renders rather
  than throwing, so this needs a dedicated live check); a pre-existing mobile
  header overflow (see below) was confirmed NOT caused by report-issue.

## Findings — UI regression

- **Sweep 7's mobile-overflow fix regressed** (medium, confirmed, fixed).
  Commit `01b1bf0` ("add Gemini Enterprise hunt link") landed a chip inside
  the header tabs after sweep 7's `min-width: 0` fix, and neither the tabs
  nor the chip got the same treatment or a narrower breakpoint rule — the
  header went from fitting at 390px back to 413px of forced horizontal
  scroll. Not caused by report-issue; report-issue's own button/panel stayed
  within bounds. Fixed by extending the existing 480px breakpoint block:
  `min-width: 0` on `.header-tabs`/`.header-tab`/`.header-tab-hunt`, hiding
  `.gemini-ent-chip-text` (keeping the spark dot, same pattern already used
  for the status pills), and tightening the status-pill padding further.
  Verified locally (static file server + headless Chrome CDP against a 390px
  viewport): scrollWidth dropped from 413px to within ~1px of the 390px
  viewport (the residual sub-pixel is clipped by the breakpoint's existing
  `overflow-x: hidden` backstop, unrelated to this fix).
- **Report-issue button has no double-click guard** (low, confirmed, fixed).
  `openPanel()` had no re-entrancy guard; a double-click fired two concurrent
  `html2canvas` captures, leaving two stacked preview images — the same
  click-flood class sweep 1/8 fixed elsewhere (chat hint chips, Threat Hunt
  exits/decisions) via re-entrancy guards, which this newer file didn't
  inherit. Fixed with the same `opening` flag pattern. The Send button was
  already correctly guarded (`submit.disabled = true` set synchronously).
  Verified locally: double-click now leaves exactly 1 preview image.
- Threat Hunt's sweep-8 double-click fixes (exit-skip, decision-dialog-stack)
  were re-checked live and still hold.

## Findings — post-sweep-9 fix re-verification

- **Next-Steps zone-name filter REGRESSED** (medium, confirmed, fixed). The
  live app leaked the real, space-separated restricted segment name
  "Tool Mgmt" (from `docs/DATA-SCHEMA.md`) verbatim in Next Steps hints,
  reproduced 3/3 times ("pivot to Tool Mgmt zone outbound HTTP user agents",
  etc.). Commit `0cf73ac`'s `_strip_zone_asset_noise` filter only catches
  underscore-joined *invented* paraphrases (`Tool_Mgmt`) or `field=value`
  syntax — it never anticipated the model using the real name's actual
  spelling verbatim. `_ZONE_RE` (which runs on every hint via
  `sanitize_output_text`) only matched the bare words "Registration"/"Tools",
  never the real multi-word segment names. Widened `_ZONE_RE` to include the
  literal names from `docs/DATA-SCHEMA.md`'s Infrastructure list
  ("Registration Hypervisors", "Tool Mgmt", the Umbrella DNS appliance name),
  ordered longest-first so alternation matches the full phrase. Mirrored the
  same widening in `alertHints.js`'s copy per CLAUDE.md's "loosen one,
  loosen both" rule for that guardrail pair.
- Redaction fix (`8d74260`) **HOLDS** — live traffic surfaced a real
  `cup2key=` token (the exact shape named in the fix's tests) and it was
  correctly redacted.
- ThousandEyes failed-fetch fix (`77d75f0`) **HOLDS** on the happy path (2
  real active alerts correctly reported, unmeasured tests flagged
  separately); the failure path itself could not be forced live against a
  working production ThousandEyes API and remains verified by code reading +
  existing unit test only, consistent with sweep 9's own caveat.

## Findings — fresh freeform chat (new question shapes, not previously tried)

Two angles never driven before this sweep: literally asking the Next-Steps
hints a prior answer generated (2-3 levels of chaining), and new question
shapes (negation, relational/multi-entity, tight time-boundary, typo/slang
mixed with a technical ask). Found the most severe fabrication bug of this
sweep:

- **A failed query still produced a confident negative with a fabricated
  time window** (high, confirmed, fixed). "Is the CTF network talking to
  the sponsor booths at all" hit an "Out-of-scope IP prefix" error
  (`sql_queries_executed=0`, nothing succeeded) on the local/AQLight lane,
  yet the answer opened with "No activity from the CTF network... in the
  last hour (16:00-17:00)" — a time window that no query ever covered, in
  direct violation of the SYSTEM_PROMPT's own explicit rule ("never combine
  a failure with a negative-finding sentence"). The prompt text was already
  correct; a smaller model on the local lane simply didn't follow it. This
  is the same bug *class* CLAUDE.md documents as previously fixed once
  already (`f3af6c8`, alert-triage contradicting its own numbers) recurring
  in a sibling agent — prompt-only enforcement isn't durable against every
  model tier. Added a **code-level override** in `llm_analyze`: when
  `context["errors"]` is non-empty and no query succeeded, the answer is
  replaced server-side regardless of what the model wrote, and confidence is
  capped at 0.2. This is now enforced structurally, not just requested in
  the prompt.
- **"Exclusive communication" claim was tautological** (medium, confirmed,
  fixed). "Are there two hosts that only talk to each other and nothing
  else" answered that one host "communicates exclusively" with another at
  confidence 0.9, backed by a query whose `GROUP BY` already included both
  IPs — so `COUNT(DISTINCT id_resp_h)=1` was guaranteed by construction, not
  evidence. Directly falsified live: the same host had 197 other real
  destinations (Amazon, Microsoft, Google, OpenDNS) when queried without the
  pair filter. Added an explicit SQL pattern to `SQL_GEN_PROMPT`: exclusivity
  questions must `GROUP BY id_orig_h` alone across the host's *full* traffic,
  never pre-filtered to a candidate pair.
- **"WiFi devices" queries searched the wrong subnet** (medium, confirmed,
  fixed). "Which two devices on the wifi have talked to each other the most"
  filtered both IPs to `10.%`, a range with zero WiFi clients in it (they
  live in `192.168.128.0/18` per `ipscope.py`'s conference-range table) — so
  the confident zero-result answer was actually "searched the wrong place,"
  not "found nothing." Added an explicit WiFi-range rule to `SQL_GEN_PROMPT`
  with the correct octet-range check.
- **Next Steps described fixing the SQL, not investigating the network**
  (low, confirmed, fixed). A query that hit two real `TYPE_MISMATCH` Athena
  errors surfaced "Correct the type mismatch in the known hosts query" and
  "Repair the truncated syntax in the known services query" as analyst-facing
  Next Steps — bug-ticket language for the tool itself, not an action an
  analyst can take. Added an explicit SYSTEM_PROMPT rule: Next Steps are
  analyst actions against the *network*, never against the query/SQL/tool.
- **Confidence didn't drop on a self-admitted scope miss** (low, confirmed,
  fixed). "Anything happen exactly at midnight" opened by admitting the
  queried window "starts at 07:00:00 UTC, missing midnight activity," but
  confidence stayed well above the SYSTEM_PROMPT's existing low-confidence
  floor for degraded answers. Extended that floor to also cover any answer
  whose own text concedes a scope miss.
- **A Next-Steps hint asked for a capability no agent has** (low, confirmed,
  fixed). "Verify sensor ingestion for active connection zones" was generated
  as a follow-up hint, but athena-hunter has no sensor/heartbeat/ingestion-
  health data source — asking it literally got an answer that quietly
  redefined "verify ingestion" as "show the connection count," which checks
  nothing resembling health. Added a hint post-filter dropping
  `sensor ingestion` / `telemetry health` / `heartbeat` phrasing, matching
  the existing `_strip_vendor_names`/`_strip_schema_noise` reject-the-
  candidate pattern.
- **Gateway/route questions naming a specific internal IP misrouted to
  thousandeyes-analyst** (medium, confirmed, fixed). Two Next-Steps hints
  naming specific internal subnets for "gateway route" auditing both routed
  to the synthetic-test agent, which answered with the same generic global
  summary unrelated to either subnet — it has no per-host query capability
  at all. Added a routing tiebreaker: a private-range IP/CIDR in the query
  always routes to athena_hunter regardless of gateway/route keywords.
- One finding (the cited "QUIC:TCP ratio ~60:40" / certificate-transparency
  claim from a null-data response) was **PARTIAL**: it traced to an
  author-written guardrail cover response (`_COVER_RESPONSES`), not an LLM
  hallucination mid-real-query as originally characterized — covers are
  deliberately plausible-sounding SOC prose and `data=None` is intentional
  there (so the guardrail can't be fingerprinted by its data shape). Left
  unfixed this sweep; the underlying concern (a cover entry with a
  suspiciously specific numeric claim) is legitimate but low-severity and
  cosmetic, and rewriting cover prose risks the guardrail's own
  non-fingerprintability property, so it's deferred rather than
  reflexively "fixed."

## Verification

`ops/run-tests.sh`-equivalent (pytest + vitest run directly): 1496 Python
tests (up from the 1444 baseline; 52 new regression tests added this sweep)
and 281 TypeScript tests (up from 270), all green. Every new fix's regression
test was confirmed to FAIL against the pre-fix code (revert-and-check) before
being trusted as a real gate — done for the zone-name widening, the
failed-query override, and all five prompt-text fixes' backing assertions.

The mobile-overflow and double-click fixes were verified live against a
local static-file copy of the app in headless Chrome at a 390px viewport
(not the deployed site, since the fix isn't there yet): header overflow
dropped from 413px to within 1px of the viewport (clipped by the existing
`overflow-x: hidden` backstop), and double-clicking the report-issue button
now leaves exactly one preview image instead of two.

The prompt-text fixes (WiFi range, exclusivity SQL, Next-Steps phrasing,
confidence-on-scope-miss, routing tiebreaker) are LLM-guided, not
deterministic code, so static verification (prompt-string assertions, the
existing test suite) cannot fully confirm the fixed *behavior* the way a
live model call can — consistent with every prior sweep's same caveat.
Recommend re-running the exact failing queries from this sweep ("which two
devices on the wifi have talked to each other the most", "are there two
hosts that only talk to each other and nothing else", "is the CTF network
talking to the sponsor booths at all") against a deployed copy of this
branch before considering those closed.

## Deferred

- html2canvas rendering quality with open blurred overlays (alert-modal,
  hunt end-dialog) underneath the report-issue panel — not independently
  verified this sweep.
- The `_COVER_RESPONSES` QUIC:TCP-ratio entry's specific-sounding numeric
  claim (FF10-001 PARTIAL) — low severity, cosmetic, deferred pending a
  decision on whether to vaguen cover prose without weakening its
  non-fingerprintability property.
- LIVE-007 (blank src/port fields on `*StorageExfil::` alert types) and
  LIVE-008 (local/AQLight lane skipping alert-triage's required answer
  format under token pressure) remain open from earlier sweeps, out of this
  sweep's UI/freeform-chat scope.

## Recommendation

Deploy `fix/qa-sweep-10-ui-and-freeform` and re-verify the LLM-guided fixes
live, especially the failed-query override (FF10-003's class was the most
severe fabrication found) and the mobile-overflow/double-click UI fixes
against the real deployed site rather than the local static copy used for
this sweep's verification. Recommend another sweep once this is deployed and
re-verified — the freeform hunter found real fabrication bugs on its first
pass at hint-chain-following and new question shapes, suggesting more remain
in that space untried.
