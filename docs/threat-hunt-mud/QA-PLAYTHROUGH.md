# Threat hunt — cold-play QA checklist

Automated coverage lives in:

- `packages/web-server/test/threatHuntPlaythrough.test.ts` — evidence-aware graph walk
- `packages/web-server/test/threatHuntEngine.test.ts` — happy-dom click-through (gates, logs modal, timeline, close codes)
- `packages/web-server/test/threatHuntConfig.test.ts` — config contract

This checklist is for **eye / motion** QA that the suite cannot judge. Run it in a real browser after a hard refresh.

## Setup (WSL)

```bash
cd /mnt/c/Users/johnr/orca/workspaces/NOCgentic/pufferfish
PORT=3010 npm run dev
# Open (Windows localhost is unreliable):
# http://$(hostname -I | awk '{print $1}'):3010/#threat-hunt
```

## fakecorp-cleartext-mcp (primary)

- [ ] Picker shows the hunt; briefing title/target look right
- [ ] Start → first feed line has alert emphasis (amber edge / one-time glow)
- [ ] Feed lines stagger in (not a single dump); cursor/scanline feel present
- [ ] Evidence chips fly from the feed to the rail (or land immediately under reduced motion)
- [ ] Glossary underline appears on first occurrence per node only; hover tip readable
- [ ] Timeline strip visible; markers dim until sources visited; active node pulses
- [ ] Path: Observed → HTTP sessions → Resolver → Device → Class traffic
- [ ] Before enough evidence, **Move to close codes** is disabled with a clear Needs N hint
- [ ] After ≥4 evidence, gate unlocks
- [ ] **View logs** → staged “querying” → captures; Esc / backdrop / Close all dismiss
- [ ] Evidence chip → Show hint highlights the right rows and scrolls to first mark
- [ ] Timeline marker click opens captures with rows pre-highlighted
- [ ] False Positive → lose dialog names True Positive as correct first move
- [ ] Play Again → True Positive → win; under-target badge if under 3:00
- [ ] Button `:active` press feedback feels solid; no layout jump on pivots

## Reduced motion

- [ ] OS/browser “prefer reduced motion” on → no chip fly / softer feed; hunt still playable

## Other hunts (smoke)

For each remaining picker entry:

- [ ] Start → walk to close codes without dead ends
- [ ] Correct close wins; one wrong close loses and teaches
- [ ] No console errors; no broken “View logs” if the room has no captures

## After checklist

```bash
npm test --workspace=@bhnoc/web-server -- threatHunt
```
