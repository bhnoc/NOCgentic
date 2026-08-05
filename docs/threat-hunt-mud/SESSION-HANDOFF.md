# Session handoff — Threat Hunt MUD (batch 2 + real logs)

**Date:** 2026-08-05  
**Branch:** `feat/threat-hunt-mud-batch-2`  
**Remote:** https://github.com/bhnoc/NOCgentic/tree/feat/threat-hunt-mud-batch-2  
**Local UI (WSL):** Windows cannot use `localhost:3010` reliably — open  
`http://<wsl-ip>:3010/#threat-hunt` (`hostname -I` in WSL). Server:  
`PORT=3010 npm run dev` from repo root.

---

## Where we left off

### Shipped on branch (committed earlier)
- Threat Hunt engine + picker
- 7 hunts in `packages/web-server/static/threat-hunt-config.js`
- Contract tests in `packages/web-server/test/threatHuntConfig.test.ts`

### Working tree (may be uncommitted — check `git status`)
- Obfuscated **Corelight** log captures on `fakecorp-cleartext-mcp` (`nodes[*].logs`)
- **View logs** modal under Evidence (Esc / backdrop / Close)
- Docs pack: `docs/threat-hunt-mud/logs/`
- Schema: optional `logs` on nodes in `ThreatHunt.d.ts`

### How real logs were found
1. Slack `#threat-hunting` (`CEHK8CLLA`) — cleartext MCP thread (host on conference floor).
2. `~/Documents/learning/palo_alto` cortex CLI:
   ```bash
   ./bin/cortex.exe xql run --hours 120 --name mcp-http --print-json \
     'dataset = corelight_http_raw | filter id_orig_h = "<src>" and uri contains "/mcp" | ...'
   ```
3. Hard obfuscation → fiction map in  
   `docs/threat-hunt-mud/logs/OBFUSCATION-MAP-CLEARTEXT-MCP.md`

**Do not** put real bearer tokens, org names, or floor IPs in git.

---

## Done this handoff (working tree — commit when ready)
- [x] Wire close elevated as a soft **HINT** block (not “SMOKING GUN”) on `http-conn`
- [x] Softened narration / evidence / result notes vs earlier spoilers
- [x] Logs open via one-click **View logs** modal (Esc / backdrop / Close)
- [x] Test asserts HINT + wire facts; `smoking gun` string still absent
- [x] Fluid-feed pass (uncommitted): staggered line streaming, alert-line
      promotion (amber edge + one-time glow), evidence chips fly from the
      feed to the rail, feed measure/scanlines/cursor, glossary underlines
      first-occurrence-per-node only, `:active` press feedback,
      `prefers-reduced-motion` fallbacks
- [x] Clickable evidence (uncommitted): chips backed by captures open the
      logs modal scoped to their source node; **Show hint** highlights the
      `evidence[].hint` substrings and scrolls to the first match. Contract
      test asserts every hint string appears verbatim in the node's logs.
- [x] Incident timeline (uncommitted): optional `timeline` on the config
      (`ThreatHuntTimelineEvent`), rendered as a strip above the feed.
      Markers reveal as their correlated nodes are visited, pulse while a
      correlated node is active, and click through to the captures with the
      event rows pre-highlighted. MCP hunt ships 5 events from the real
      `ts` rows; narration reconciled to the true 90m window (289 requests).
      Contract test grounds every event's nodes + hints in the config.
- [x] Config renders everything (uncommitted): engine chrome copy moved to
      `DEFAULT_UI` with per-hunt `config.ui` overrides; `warnConfigGaps()`
      console-warns at mount on broken refs (exits, timeline nodes, hints
      not in logs, unknown ui keys). Authoring guide `threat-hunt-mud.md`
      rewritten for the NOCgentic tree (logs/hint/timeline/ui contract).
      A new hunt is now purely: append a config object, run the tests.
- [x] This file: `docs/threat-hunt-mud/SESSION-HANDOFF.md`

## Next session — start here

### 0. Playthrough QA (automated + cold-play)
- Automated: `npm test --workspace=@bhnoc/web-server -- threatHunt`
  (`threatHuntPlaythrough` + `threatHuntEngine` + contract tests).
- Manual eye/motion checklist: [`QA-PLAYTHROUGH.md`](QA-PLAYTHROUGH.md)
  (WSL IP `:3010/#threat-hunt`). Start with `fakecorp-cleartext-mcp`.

### 1. QA the config — everything must align and make sense
The engine renders 100% from `window.THREAT_HUNTS`; a config inconsistency
is now a player-visible bug. Read `threat-hunt-config.js` hunt by hunt as an
editor, not a linter (tests already cover structure):

- [x] **Numbers agree everywhere** (editorial pass 2026-08-05). MCP: 289 /
      90m / 16:42–18:12. Other six: briefing ↔ start narration anchors
      aligned (6m/3 attempts, 12m WirePipe, ~3 day beacon, SC-77419,
      same-minute dual Log4j, 40m RIVERTIDE). Log packs still only on MCP.
- [ ] **Narrations match their logs.** Every claim a node's narration makes
      should be checkable in that node's capture (when it has one); nothing
      in a capture should contradict the narration
- [ ] **Timeline reads as one coherent story** in order (16:41 → 18:14 for
      MCP); labels are facts, no tip-off / close-code leaks
- [ ] **Evidence labels/details** match what the logs actually show; `hint`
      substrings point at the *right* rows, not just any match
- [ ] **Glossary coverage**: terms used in narration/briefing that a walk-up
      player won't know all have entries; no orphan entries that never match
- [x] **Voice**: third person / no player imperatives / no "Three surfaces"
      / no "Evidence is on the table" — applied across all 7 hunts
      (playthrough story tests lock this in)
- [x] **OPSEC re-sweep** (2026-08-05): remapped MCP dests to TEST-NET-3
      `203.0.113.x`, Zeek UIDs to `Cfict*`, rivertide host off real
      `azure.com`; contract test now forbids live public IPs / azure.com /
      unreacted mcpk_ / password= values / non-.example emails
- [ ] Fix what you find in config only — engine changes should not be needed;
      run `npm test --workspace=@bhnoc/web-server -- threatHuntConfig` after

### 2. Play-test the cold read
- [ ] Hard-refresh → `fakecorp-cleartext-mcp` → Evidence → View logs
- [ ] Confirm HINT in modal; close is frictionless (Esc/backdrop)
- [ ] Timeline assembles as sources are visited; markers click through to
      highlighted rows
- [ ] Confirm close still earns True Positive

### 3. Continue log pipeline for other hunts
Same pattern as MCP, one hunt at a time:

| Priority | Hunt id | Likely source |
| --- | --- | --- |
| Next | `northlab-cleartext-siem-login` | Slack + `corelight_http_raw` cleartext SIEM login |
| Then | `fakecorp-supplychain-dns` | DNS + Suricata / ET rows |
| Then | `northlab-singleton-c2` | DDNS/C2 + peer-negative search |
| Then | `stagecast-license-pii-http` | cleartext license POST |
| Then | `noc-log4j-sensor-test` | dual-engine Log4j to test host |
| Then | `rivertide-azure-background` | corp Azure/DNS + proxy |

Rules: facts from Slack/XQL only; fiction for identity; soft **HINT** labels OK  
(not “SMOKING GUN”); logs behind a one-click modal under Evidence.

---

## Key files

| Path | Role |
| --- | --- |
| `packages/web-server/static/threat-hunt-config.js` | Hunt registry + embedded obfuscated `logs` |
| `packages/web-server/static/threat-hunt.js` | Engine (glossary, picker hook, logs modal) |
| `packages/web-server/static/app.css` | `.hunt-logs-*`, `.hunt-log-pre` |
| `packages/web-server/test/threatHuntConfig.test.ts` | Contract + OPSEC + log shape |
| `packages/web-server/test/threatHuntPlaythrough.test.ts` | Evidence-aware graph walk (all hunts) |
| `packages/web-server/test/threatHuntEngine.test.ts` | happy-dom UI click-through |
| `docs/threat-hunt-mud/QA-PLAYTHROUGH.md` | Manual cold-play checklist |
| `docs/threat-hunt-mud/FROM-SLACK-TO-MUD.md` | Authoring procedure |
| `docs/threat-hunt-mud/logs/` | Obfuscated log packs + maps |
| `~/Documents/learning/palo_alto` | `cortex` XQL / investigations (gitignored artifacts) |
| `~/Documents/projects/black-hat-slack-bot` | Slack bot token for `#threat-hunting` |

---

## QA notes already known
- Obfuscation audit on MCP logs: clean (no real org/IP/token strings).
- Vitest `threatHuntConfig` was green (60+ tests) before this handoff.
- Windows ↔ WSL: use WSL IP, not `127.0.0.1:3010`.
- Epistemic: “write tools advertised” was **not** proven in the Slack MCP  
  thread or truncated `tools/list` replies — prefer cleartext bearer +  
  full path set on `:80` as the earned close, discovered by reading logs.

---

## Suggested first commands next session

```bash
cd /mnt/c/Users/johnr/orca/workspaces/NOCgentic/pufferfish
git checkout feat/threat-hunt-mud-batch-2
git status
PORT=3010 npm run dev
# browser: http://$(hostname -I | awk '{print $1}'):3010/#threat-hunt
npm test --workspace=@bhnoc/web-server -- threatHunt
```

Then: playthrough checklist ([`QA-PLAYTHROUGH.md`](QA-PLAYTHROUGH.md)),
config QA (item **1**), cold-play (item **2**), then item **3**
(`northlab-cleartext-siem-login` logs).
