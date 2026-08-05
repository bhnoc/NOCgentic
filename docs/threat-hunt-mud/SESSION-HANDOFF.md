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
- [x] This file: `docs/threat-hunt-mud/SESSION-HANDOFF.md`

## Next session — start here

### 1. Play-test the cold read
- [ ] Hard-refresh → `fakecorp-cleartext-mcp` → Evidence → View logs
- [ ] Confirm HINT in modal; close is frictionless (Esc/backdrop)
- [ ] Confirm close still earns True Positive

### 2. Continue log pipeline for other hunts
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
npm test --workspace=@bhnoc/web-server -- threatHuntConfig
```

Then: cold-play item **1**, then start item **2** (`northlab-cleartext-siem-login` logs).
