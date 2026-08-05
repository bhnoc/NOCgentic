# QA sweep 7 — live UI, the 80% path

Scope: drive the LIVE app's actual UI in a real browser (headless Chrome over
CDP, no npm deps, same pattern as `tests/ui/*.mjs`), focused on what most
users actually do rather than edge cases: land on the page, click or type a
question, read the answer, click a follow-up hint, check the alert sidebar,
open a card. Read-only against `https://ng.bhnoc.com`. Fix committed to
`fix/qa-sweep-live-findings`, not deployed.

## Method

Built `tests/ui/live/` (see its README): a CDP helper plus three drivers.
`golden-path.mjs` walks the primary flow end to end — starter chip click,
answer render, Next Steps hint click, alert card open/close. `mobile-and-typed.mjs`
covers a 390px mobile viewport and a typed-and-Enter query (the other half of
how a real question gets asked, versus clicking a chip). `hint-chip-timing.mjs`
is a diagnostic that samples the hint-chip DOM count over time, since hints
populate asynchronously and a driver that checks once right at answer-settle
can misdiagnose a timing gap as a missing feature.

## Findings

**Mobile horizontal scroll on every visit (confirmed, fixed).** On a 390px
viewport (iPhone-class, the majority of "checking on my phone" traffic), the
page had 92px of forced horizontal scroll (`document.body.scrollWidth: 482`
against `innerWidth: 390`). Root cause was the same CSS trap at two levels:
grid items (`header`, `main`, `.sidebar`) default to `min-width: auto`, which
sizes them to their content's max intrinsic width rather than the grid track,
so the single-column mobile layout never actually constrained them to the
viewport. Fixing that dropped the overflow from 482px to 428px, but the
header itself was still ~20px over: brand + logo + the two-tab nav + two
status pills have no shrink allowance in a 390px row even with the existing
768px breakpoint's font/padding reductions. Fixed by adding `min-width: 0`
to the three grid items at both breakpoints where the layout collapses to a
single column (768px and 480px), then hiding the status pills' label text at
480px (the color-coded dot alone still carries connected/degraded/down
state) and tightening tab/pill padding to match the stylesheet's existing
pattern of progressive size reduction at that breakpoint.

Isolated and proved each layer of the fix independently by injecting CSS
live against production (not the local stub) before touching the file:
482px -> 428px (grid min-width) -> 411px (partial header squeeze) -> 390px
(the header content correction). Then re-verified the exact CSS actually
committed to the file reproduces the 390px result against live production
data (real alert cards, real header state), not just a synthetic page.

Confirmed the same header-driven overflow affects the Threat Hunt tab too
(482px, same measurement), consistent with the root cause being shared
header markup rather than something specific to the chat view.

## Everything else this sweep drove, and found no defect in

- **Golden path end to end**: starter chip click -> real (non-cover, non-thin)
  answer -> Next Steps hint chip appears (after the expected async delay,
  confirmed via `hint-chip-timing.mjs`: 0 at settle, 5 within 3s) -> clicking
  it submits a new query -> completes. All passed against three different
  starter-chip draws (athena-hunter, thousandeyes-analyst, and alert-triage
  answers all rendered correctly).
- **Alert sidebar and popup**: 20+ real cards rendered, clicking one opens
  the modal with real fields (source, IPs, port, network) and 5 real Hunt
  From Here chips, Escape closes it. Matches the desktop-only assertions
  already covered by `tests/ui/alert-popup.mjs` against a stub — this
  confirms the same mechanics hold against live data too.
- **Mobile chip tap**: the same click handler fires correctly under a
  touch-shaped click event on the 390px viewport (independent of the layout
  bug above — the interaction works, only the layout was broken).
- **Typed query + Enter**: submits correctly, echoes the exact typed text,
  locks the send button, and produces a real answer. This is the other half
  of how users ask questions and it was not previously covered by any
  existing UI test (`tests/ui/quick-pick-autosubmit.mjs` only covers the chip
  path).
- **Live re-verification of sweep 1's athena-hunter fix**: this sweep's
  golden-path run against production (before this sweep's own fix was
  deployed) hit the exact "query failed" path from sweep 1 again on a fresh
  question and got the correct fixed behavior: "The lookup for DNS answer IPs
  could not be completed," no error leak, no false negative. Confirms that
  fix is holding under real live traffic, not just the original repro query.

## Verification

`ops/run-tests.sh`: 1444 Python + 170 TypeScript tests, all green, no
regressions. `tests/ui/run.sh` (the existing stub-based desktop UI gate,
covering quick-pick chips, lane swap, and the full alert-popup drag/close/
chip-click mechanics): all green, confirming this sweep's CSS change does
not affect desktop-viewport layout or behavior. The mobile fix itself was
verified three ways before commit: isolated CSS injection against live
production at each step of the diagnosis, the exact file diff re-tested
against live production data, and a final clean run of the full
`tests/ui/live/run.sh` golden path (which runs at desktop viewport, so it
doesn't re-check the mobile width itself, but confirms nothing broke).

Not yet verified: the fix has not been re-checked against a deployed copy
of this branch, per instructions to commit but not deploy this sweep.

## Not covered this sweep

- The Threat Hunt tab's own interactions (selecting a scenario, running a
  drill) were not driven end to end — only confirmed it renders and shares
  the header overflow bug with the chat view. Worth a dedicated pass if
  Threat Hunt is a meaningfully used surface.
- No tablet-width viewport (e.g. iPad, ~768-1024px) was tested; only desktop
  (1280px) and phone (390px) were checked. The 768px breakpoint is where the
  grid first collapses to one column and is the more likely place for a
  narrower version of the same class of bug.
- Landscape mobile orientation was not tested.
- This sweep did not repeat sweep 1's dynamic HTTP-driven query-content
  checks (answer correctness, routing, alert-triage verdict consistency) —
  those already have their own coverage from sweep 1 and were only
  incidentally re-confirmed once (the DNS-lookup-failure case) as a side
  effect of driving the golden path here.

## Recommendation

This fix is committed but not deployed, per instructions. When ready to
deploy: redeploy, then re-run `tests/ui/live/run.sh` and a mobile-viewport
check (`mobile-and-typed.mjs` or a fresh manual CDP check) against the live
instance to confirm the body-scroll-width fix holds against whatever the
live alert feed and header state look like at deploy time, the same way
sweep 1's fixes were re-verified live after their own deploy. A follow-up
sweep should cover the two gaps above (Threat Hunt interactions, tablet
width) if there's appetite for more UI-layer coverage.
