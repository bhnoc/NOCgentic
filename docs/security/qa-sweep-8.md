# QA sweep 8 — Threat Hunt UX, click-flood class of bug

Scope: continue the UI-focused sweep, this time on the Threat Hunt feature
(landed on main since sweep 7 — `feat/threat-hunt-mud-batch-2`), a click-only
walk-up investigation drill across 7 scenarios. Drove the live app in real
headless Chrome (`tests/ui/live/`), focused on what the design doc
(`docs/threat-hunt-mud/threat-hunt-mud.md`) explicitly promises: no punishing
dead ends, honest wrong-answer feedback, gated evidence with a stated reason,
a timeline strip, glossary hover tips. Fixes committed, not deployed.

## Method

Added three drivers to `tests/ui/live/`:

- `threat-hunt-playthrough.mjs` — full end-to-end play of one scenario:
  picker → briefing → start → walk exits → open an evidence chip's log
  capture (past its staged loading delay) → reach the decision node →
  choose an action → read the end dialog → Play Again. Ran against all 7
  scenarios.
- `threat-hunt-features.mjs` — targeted probe of glossary hover tips, the
  `requiresEvidence` gate's stated reason, and the timeline strip's
  reveal/click/caption/modal behavior.
- `threat-hunt-edge-cases.mjs` — leaving mid-hunt and re-entering, and
  rapid double-clicks on an exit and on a decision action (the same class
  of click-flood bug found in sweep 1's chat hint chips).

## Findings

**Double-click on an exit button skips a node (confirmed, fixed).**
`enterNode()` had no re-entrancy guard: two click events from a double-click
both fire before `renderNodePanel()`'s DOM rebuild can disable the button
(both are queued in the same task), so a double-click called `enterNode()`
twice and silently advanced through two nodes at once, duplicating whichever
node's narration happened to render last rather than the one actually
clicked. First attempt at a fix (`if (id === nodeId) return`) broke 12
existing tests: `start()` pre-sets `nodeId = config.startNode` *before*
calling `enterNode(config.startNode)` for the very first render, so guarding
on `nodeId` directly skipped the start node's own narration and evidence.
Fixed by tracking the last node actually *entered* (`lastEnteredNode`)
separately from the current `nodeId`, reset in `start()`. Verified against
the real committed file: feed line count dropped from 6 (duplicate
narration line) to 5 (correct) on a scripted double-click.

**Double-click on a decision action stacks two end dialogs (confirmed,
fixed).** Same root cause, different function: `choose()` had no guard
against being called twice before `phase` flips to `'ended'` and the buttons
disable. Fixed with an early-return `if (phase !== 'playing') return;` at
the top of `choose()`. Verified: end dialog overlay count dropped from 2 to
1 on a scripted double-click.

Both fixes were checked against a subtlety before landing: does any real
hunt config legitimately re-enter the same node (a genuine MUD-style
revisit)? Loaded all 7 configs and confirmed zero exits point back at their
own containing node (`exit.to === id`), so the `lastEnteredNode` guard only
ever blocks the literal double-click case, never a legitimate two-step
back-and-forth between different rooms.

**No aria-live region on the hunt feed (logged, not fixed).** The narration
feed (`#hunt-feed`) never announces new content to a screen reader; only the
logs-modal loading spinner has `aria-live`. Real gap, lower severity, and
this sweep's focus was general UX rather than a dedicated accessibility
pass — logged in `qa/findings/sweep3_ui.json` (UI-003) for a future sweep.

## Everything else driven, and found no defect in

- **All 7 scenarios play through cleanly end to end**: real briefings, real
  log captures that resolve past the staged 700-1400ms fake-loading delay
  with actual log lines (not just the spinner), "Show hint" highlighting
  marks the right substrings, decision node offers exactly the documented
  3 containment actions, wrong-answer dialogs correctly show a "Correct
  first move" teaching note (confirmed live on 2 of 7 scenarios where the
  deliberately-picked "last action" was actually wrong), Play Again returns
  to a playable state.
- **Glossary hover tips**: render as focusable `.hunt-term` spans with a
  `data-tip`, confirmed keyboard-accessible (non-zero tabindex), no
  duplicate underlining of a repeated term within one node's narration.
- **Timeline strip**: hidden until a hunt has timeline events, reveals
  markers as their correlated nodes are visited, clicking a revealed marker
  opens that node's log captures with hint substrings highlighted, exactly
  as documented.
- **Leave mid-hunt and re-enter**: returns cleanly to the picker, and
  re-entering the same scenario starts genuinely fresh (0 evidence, 0:00
  timer) rather than resuming stale state from the abandoned run.
- **Structural check across all 7 configs**: every non-decision node has at
  least one evidence item (the design doc's "every node must be worth
  visiting, no punishing dead ends" rule holds structurally, not just by
  spot-check).

## Verification

`ops/run-tests.sh`: 1444 Python + 270 TypeScript tests (up from 258 before
this sweep's fix attempt exposed the `nodeId`-guard mistake and forced the
correct `lastEnteredNode` design), all green. Both edge-case fixes were also
re-verified against the actual committed file served locally (not just
reasoned about), confirming the specific before/after counts (6→5 feed
lines, 2→1 end dialogs) against real DOM state, not a synthetic assertion.

Not yet verified against a live deployed copy — fixes are committed,
deployment withheld per instructions for this sweep.

## Not covered this sweep

- The accessibility gap (UI-003) beyond identifying it — no fix attempted.
- Tablet-width viewport and landscape mobile orientation for the Threat Hunt
  view specifically (sweep 7 flagged these as general gaps; still open).
- Keyboard-only full playthrough (tab-to-focus + Enter on every exit/action,
  not just checking tabindex is nonzero) was not driven end to end.
- Rapid-click stress beyond exactly 2 clicks (3+, or clicking two different
  exits in quick succession) was not tested; the fix should generalize
  (any click after the first `enterNode`/`choose` call is a no-op while
  `lastEnteredNode`/`phase` reflect the new state) but wasn't separately
  proven at higher click counts.

## Recommendation

These two fixes are real correctness bugs in a shipped, playable feature and
are lower-risk to deploy than they are to leave live (a silently-skipped
room or a doubled end dialog undermines the "careful player wins on the
first run" design promise). Deploy when ready, then re-run
`tests/ui/live/threat-hunt-edge-cases.mjs` against the live instance to
confirm the fix holds there too, the same way every prior sweep's fixes were
re-verified live after their own deploy.
