# Threat hunt MUD — handoff bundle

A walk-up, click-driven, ~3-minute "threat hunt as code" game, built and
play-tested in the Black Hat NOC design-system repo
(`noc-ui-kit`, branch `the-mud-on-rails`). This folder is the portable core
for integrating it into NOCgentic.

## The idea

A MUD skeleton re-skinned as security operations: rooms are log sources,
exits are investigative pivots, inventory is evidence, and the final
encounter is a containment decision. The defining property is that **the
game is data** — the engine is content-free and reads one config object, so
any threat hunt (real or authored) becomes playable by writing a config.

## Files

| File | What it is |
| --- | --- |
| `SESSION-HANDOFF.md` | **Start here next session** — branch, log pipeline status, next hunts, QA notes. |
| `PLAN.md` | The original implementation plan (architecture, decisions, scope). |
| `FROM-SLACK-TO-MUD.md` | Memo: take a Slack threat-hunt thread → obfuscate → rooms → close code → ELI5 glossary → ship config (worked FAKE CORP example). |
| `threat-hunt-mud.md` | Authoring guide: how a hunt plays, the config contract, voice rules, how to add hunts. |
| `ThreatHunt.d.ts` | The "MUD as code" schema: `ThreatHuntConfig` (nodes, exits, evidence, decision, endings, glossary). This is the contract to preserve. |
| `threat-hunt-config.js` | Reference hunt: cleartext MCP / FAKE CORP asset (close codes, hard obfuscation, ELI5 glossary). |
| `ThreatHunt.jsx` | Reference engine (~150 lines of React). Browser-global style from the design-system repo — a porting reference, not a drop-in module. |

## Integration notes

- The engine's only dependencies are seven design-system primitives
  (`Card`, `LogStream`, `Tag`, `Button`, `Badge`, `Dialog`, `Separator`).
  Swap them for NOCgentic's equivalents and convert the globals to imports;
  the game logic (`enterNode`, evidence dedupe, `requiresEvidence` gating,
  `choose`, soft timer) ports unchanged.
- `threat-hunt-config.js` sets a `window` global for script-tag loading.
  For this codebase, convert it to a JSON file or ES module validated
  against `ThreatHunt.d.ts`.
- Game rules worth preserving: no typing, every node yields evidence (no
  punishing dead ends), the clock warns but never fails, wrong containment
  choices explain themselves and name the correct first move, equal visual
  weight on decision buttons so styling never leaks the answer.
- The fully wired, playable version (nav item, toast pipeline, compact
  layout, contract tests) lives in the design-system repo under
  `ui_kits/noc-console/` if you want to see it running: serve the repo root
  and open `ui_kits/noc-console/index.html`, sidebar → Threat hunt.
