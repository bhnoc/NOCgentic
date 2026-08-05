# Threat hunt as code

The NOC Console carries a **Threat hunt** section: a walk-up, click-driven
investigation drill designed to finish in about three minutes. It borrows the
skeleton of a MUD — rooms, exits, an inventory, one decisive encounter — and
re-skins every part of it as security operations. Rooms are log sources.
Exits are pivots. The inventory is evidence. The encounter is a containment
decision.

The defining property is that **the game is data**. The engine
(`packages/web-server/static/threat-hunt.js`) contains no scenario content; it
reads one config object and renders everything — briefing, rooms, evidence,
log captures, hints, the incident timeline, and even the chrome copy. Any
threat hunt — real or authored — becomes playable by appending a config that
matches the contract in `docs/threat-hunt-mud/ThreatHunt.d.ts` to the registry
in `packages/web-server/static/threat-hunt-config.js` (`window.THREAT_HUNTS`).
The reference instance is `fakecorp-cleartext-mcp`, built from a real hunt.

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

Full types live in `docs/threat-hunt-mud/ThreatHunt.d.ts`. Summary:

| Field | Meaning |
| --- | --- |
| `id` | Stable scenario id. |
| `meta.title` | Scenario title, sentence case. |
| `meta.briefing` | The walk-up paragraph: the alert, the goal, the target time. |
| `meta.targetSeconds` | Soft time target. Over it, the timer badge turns amber. Never a hard fail. |
| `glossary` | Optional ELI5 map. First occurrence per node underlines with a hover tip. |
| `timeline` | Optional incident-timeline events `{ id, t, label, nodes?, hint?, tone? }`. Markers reveal as their correlated nodes are visited; clicking one opens the node's captures with the `hint` substrings highlighted. Strip hides when absent. |
| `ui` | Optional chrome-copy overrides (opening line, logs modal copy, timeline labels, …). Engine defaults cover every key. |
| `startNode` | Id of the first node entered on start. |
| `nodes` | Map of node id → node. Every `exits[].to` must name a key here. |
| `nodes[].name` | Panel-header name of the surface ("Proxy logs"). |
| `nodes[].tag` | Bracketed mono source tag for the feed ("[proxy]"). |
| `nodes[].narration` | Appended to the log feed on entry. |
| `nodes[].evidence` | `{ id, label, detail, hint? }[]`, collected once each, shown as chips. When the node has `logs`, the chip is clickable and reopens those captures; `hint` substrings drive the modal's "Show hint" highlight. |
| `nodes[].logs` | Optional obfuscated capture blocks `{ id?, title, lines }[]`. Evidence chips on that room become clickable and open the captures modal; timeline markers can reopen them too. |
| `nodes[].exits` | `{ to, label, requiresEvidence? }[]` pivot buttons. |
| `nodes[].isDecision` | Marks the containment node. Exactly one should be reachable. |
| `nodes[].actions` | `{ id, label, correct?, resultNote }[]`. Exactly one `correct: true`. |
| `endings` | `win` / `lose` (`timeout` reserved), each `{ title, narration }`. |

Grounding rules enforced by the contract tests
(`packages/web-server/test/threatHuntConfig.test.ts`) and re-checked with
console warnings at mount: every exit resolves to a node, every timeline
event names real nodes, and every `hint` substring (evidence or timeline)
appears verbatim in the correlated node's log lines. A hunt that omits
`logs` / `timeline` / `hint` simply renders without those surfaces — nothing
else changes.

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

1. Append a config object to `window.THREAT_HUNTS` in
   `packages/web-server/static/threat-hunt-config.js`, matching the contract
   above. The picker, briefing, rooms, evidence chips, logs modal, hints,
   and timeline all render from it — no engine change, ever.
2. Follow `FROM-SLACK-TO-MUD.md` for sourcing: facts from the Slack thread /
   XQL rows only, fiction for identity, hard obfuscation before anything
   lands in git (see `logs/OBFUSCATION-MAP-*.md`).
3. Run `npm test --workspace=@bhnoc/web-server -- threatHuntConfig`. The
   contract tests validate the graph, close codes, OPSEC strings, and hint /
   timeline grounding. The engine also console-warns about broken references
   at mount as a second net.

`logs`, `timeline`, `hint`, and `ui` are all optional — start with the graph
and add capture surfaces as real data is obfuscated.
