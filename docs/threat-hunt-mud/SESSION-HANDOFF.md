# Session handoff — Threat Hunt MUD (batch 2 + real logs)

**Date:** 2026-08-05  
**Branch:** `feat/threat-hunt-mud-batch-2`  
**Remote:** https://github.com/bhnoc/NOCgentic/tree/feat/threat-hunt-mud-batch-2  
**Local UI (WSL):** `http://<wsl-ip>:3010/#threat-hunt` (`hostname -I` in WSL).  
Server: `PORT=3010 npm run dev` from repo root. **Hard-refresh** after config/engine changes.

---

## Where we left off

### Full-length (all 7 MUDs)
Every hunt ships `nodes[*].logs`, evidence `hint`s, and an incident `timeline`.
Captures open from **Evidence chips** (and timeline markers) — there is **no**
separate View logs button.

| Hunt id | Close | Notes |
| --- | --- | --- |
| `fakecorp-cleartext-mcp` | True Positive | Gold standard |
| `northlab-cleartext-siem-login` | BH Benign | 8m / 3 usernames / :8001 |
| `fakecorp-supplychain-dns` | True Positive | Two DNS bursts ~2h apart |
| `northlab-singleton-c2` | True Positive | ~3 day DDNS beacon |
| `stagecast-license-pii-http` | BH Benign | SC-77419 /activate.php |
| `noc-log4j-sensor-test` | BH Benign | Dual-engine same minute 23:20 |
| `rivertide-azure-background` | BH Benign | 37m corp Azure/DNS |

### Engine UX (scalable)
- Evidence chips with `sourceLogs` → clickable → logs modal (+ Show hint)
- Timeline markers → same modal (auto-hint)
- Contract test: every evidence-bearing room must ship `logs`; timeline ≥3
- Gemini Enterprise card stays new-tab only (no iframe)

### Packs / maps
Under `docs/threat-hunt-mud/logs/` — see `README.md`.

---

## Next session (optional)
- [ ] Cold-play each hunt once (`QA-PLAYTHROUGH.md`)
- [ ] Commit working tree if not yet committed
- [ ] Narration polish / glossary orphans if cold-play finds drift

## Suggested commands

```bash
cd /path/to/NOCgentic
PORT=3010 npm run dev
# http://$(hostname -I | awk '{print $1}'):3010/#threat-hunt
npm test --workspace=@bhnoc/web-server -- threatHunt
```
