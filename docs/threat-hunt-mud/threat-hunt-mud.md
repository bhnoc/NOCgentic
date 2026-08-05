# Threat hunt as code

The NOC Console carries a **Threat hunt** section: a walk-up, click-driven
investigation drill designed to finish in about three minutes. It borrows the
skeleton of a MUD — rooms, exits, an inventory, one decisive encounter — and
re-skins every part of it as security operations. Rooms are log sources.
Exits are pivots. The inventory is evidence. The encounter is a containment
decision.

The defining property is that **the game is data**. The engine
(`ui_kits/noc-console/ThreatHunt.jsx`) contains no scenario content; it reads
one config object and renders it. Any threat hunt — real or authored — becomes
playable by writing a config that matches the contract in
`ui_kits/noc-console/ThreatHunt.d.ts`. The reference instance is
`ui_kits/noc-console/threat-hunt-config.js`, which replays alert `A-2291`
(credential stuffing, `41.2.19.7 → guest-portal`) from the console's mock data.

## How a hunt plays

1. A briefing card states the alert and the goal, with a soft time target
   (`meta.targetSeconds`, 180 by default). One button starts the hunt.
2. The player lands on `startNode`. Each node appends its `narration` to a
   mono log feed and deposits its `evidence` into a de-duplicated set shown
   as chips. Outbound pivots render as buttons — nothing is typed.
3. Some pivots carry `requiresEvidence: n` and stay disabled, with the reason
   stated, until the player has collected `n` evidence items. This is the only
   gate in the system; there is no way to lose by exploring.
4. The decision node (`isDecision: true`) replaces pivots with containment
   actions, all rendered with equal visual weight so styling never leaks the
   answer. Choosing one ends the hunt: a toast fires through the console's
   shared action pipeline, and an end dialog reports the outcome, elapsed
   time, evidence count, and — on a wrong call — the correct first move.
5. The clock never fails a hunt. Past the target it flips the timer badge
   from `ok` to `warn`, nothing more. Play again restarts instantly.

## The config contract

Full types live in `ui_kits/noc-console/ThreatHunt.d.ts`. Summary:

| Field | Meaning |
| --- | --- |
| `id` | Stable scenario id. |
| `meta.title` | Scenario title, sentence case. |
| `meta.briefing` | The walk-up paragraph: the alert, the goal, the target time. |
| `meta.targetSeconds` | Soft time target. Over it, the timer badge turns amber. Never a hard fail. |
| `startNode` | Id of the first node entered on start. |
| `nodes` | Map of node id → node. Every `exits[].to` must name a key here. |
| `nodes[].name` | Panel-header name of the surface ("Proxy logs"). |
| `nodes[].tag` | Bracketed mono source tag for the feed ("[proxy]"). |
| `nodes[].narration` | Appended to the log feed on entry. |
| `nodes[].evidence` | `{ id, label, detail }[]`, collected once each, shown as chips. |
| `nodes[].exits` | `{ to, label, requiresEvidence? }[]` pivot buttons. |
| `nodes[].isDecision` | Marks the containment node. Exactly one should be reachable. |
| `nodes[].actions` | `{ id, label, correct?, resultNote }[]`. Exactly one `correct: true`. |
| `endings` | `win` / `lose` (`timeout` reserved), each `{ title, narration }`. |

## Authoring rules

The narration is console copy and follows the system voice defined in the
root `README.md`:

- Third person, present tense, **no direct references to the player**.
  `Auth log shows 2,904 failures`, never `You see 2,904 failures`.
- Numbers first, nouns second. No exclamation marks, no emoji.
- Containment actions come from the fixed vocabulary:
  `Acknowledge · Isolate · Allow · Block · Escalate · Dismiss`.
- Machine values (IPs, rule ids, rates) read as machine values; the feed is
  already monospace.
- Every node must be worth visiting. A source that shows nothing still rules
  something out — give it an evidence item that says so. No punishing dead
  ends; wrong turns cost seconds, not progress.
- Wrong containment actions get honest `resultNote`s that teach: state why
  the action is reasonable and why it is not the right first move *here*.

Design guidance drawn from long-running MUDs, applied here:

- Three to six nodes fit the three-minute target. One `requiresEvidence`
  gate before the attribution or decision step is enough structure.
- Uncertainty should be manageable, not random: the evidence must genuinely
  point at the correct action, so a careful player wins on the first run.
- The decision is the game. Make the wrong options plausible.

## Adding a new hunt

1. Copy `ui_kits/noc-console/threat-hunt-config.js`, keep the shape, replace
   the content. Expose it on its own global
   (`window.THREATHUNT_MY_SCENARIO`).
2. Load it from `ui_kits/noc-console/index.html` next to the existing config
   script tag.
3. Point the view at it: `<ThreatHunt config={window.THREATHUNT_MY_SCENARIO}
   onAction={push} />`. A scenario picker is a deliberate non-goal of the
   reference implementation; wiring several configs to a `Select` is a
   straightforward extension.

No engine change is required, and no change to `_ds_bundle.js` — UI-kit files
are loaded as source and are not part of the component bundle hash.
