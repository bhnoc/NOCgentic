# Handoff — Shadow the Hunter MUD (next session)

**Date:** 2026-08-01  
**Status:** P0 implemented — branching graph + consequences + Marty rewind  
**Live mock:** http://localhost:3106/  
**ELI5 API:** http://localhost:3107/health  
**Package:** `docs/mocks/shadow-packages/sth-20260801-host-sweep-fp/`  
**UI:** `docs/mocks/06-shadow-hunter/index.html`

### P0 shipped (this session)
- Linear `beats[]` replaced by **node graph** `NODES` (`G0`–`G5` + `B1`–`B8`)
- Off-path choices enter consequence rooms with **flags** / time penalties
- **↩ Change decision** on breadcrumbs + confirm modal (rewrite future)
- Keyboard **R** rewinds last decision; timer pauses on modal
- Terminus badges: Clean first pass / Time traveler / Messy but finished / Cautious closer / Knows flip conditions
- Preserved: move+integrity tags, choice ELI5, select→AI ELI5 (`history`+`flags` in client_context), stance counters

---

## 1. What we already built (do not lose)

| Piece | Where |
|-------|--------|
| Curated hunt package (tokenized) | `docs/mocks/shadow-packages/sth-20260801-host-sweep-fp/` |
| Operator redaction map (gitignored) | `…/redaction-map.json` |
| MUD 3‑min tour UI | `docs/mocks/06-shadow-hunter/index.html` |
| Choice ELI5 under every option | same |
| Forensic tags: **move** + **integrity** | Triage/Observe/… + Non-destructive / Destructive / State-changing |
| Side breadcrumbs + DATA / GUESS / ACT counters | same |
| Select-text → AI ELI5 with full package context | `eli5_server.py` :3107 |
| Compose services | `docs/mocks/docker-compose.mocks.yml` (3106 UI, 3107 ELI5) |
| Design docs | `docs/SHADOW-THE-HUNTER-DESIGN.md`, PDF proposal |

**P0 done:** real branching + rewind. Remaining polish is P1/P2 below.

---

## 2. Product goal (P0 met; P1+ open)

Branching forensic MUD where:

1. ~~Clear **golden path**~~  
2. ~~Off-path **consequences**~~  
3. ~~**Rewind** (Marty McFly)~~  
4. ~~Breadcrumbs timeline + data/guess/act~~  
5. Still ~**3 minutes** for a clean golden run; wanderers can take longer.

---

## 3. Golden path (canonical)

**Package story:** Host Sweep FP — zone protection to public DNS, agentless Mac, SaaS/MDM profile → false positive, do not isolate.

### Golden sequence (G0 → G5)

| ID | Stop | Golden choice (key) | Move | Integrity | Stance | Teaching beat |
|----|------|---------------------|------|-----------|--------|---------------|
| **G0** | STATION | 1 — All aboard | Learn | Non-destructive | META | Buy into the tour |
| **G1** | TRIAGE | 1 — Open #1 Host Sweep | Triage | Non-destructive | DATA | Sort queue; pick teachable lead |
| **G2** | CASE | 1 — Laptop DNS / not LAN sweep | Hypothesize | Non-destructive | DATA | Read remotes before act |
| **G3** | IDENTITY | 1 — Normal Mac / thin telemetry | Observe | Non-destructive | DATA | Agentless ≠ APT |
| **G4** | TRAFFIC | 1 — SaaS/MDM supports FP | Correlate | Non-destructive | DATA | Second source agrees |
| **G5** | TERMINUS | 1 — FP close with disproof | Decide | State-changing | DATA | Close ticket, don’t destroy host |

**Golden integrity signature:**  
`ND · ND · ND · ND · ND · State-changing`  
**Zero destructive.** That’s the forensic moral.

**Golden end state:**  
`disposition = false_positive`, `confidence ≈ 0.85`, `isolate = false`, badge **“Clean first pass”**.

### Alternate “acceptable” terminus (still “good enough”)

| Choice | Outcome |
|--------|---------|
| G5 · 2 Watch 24h | Soft success — **Watch · Non-destructive**, badge “Cautious closer” |
| G5 · 3 What would flip mind | Soft success — **Learn**, badge “Knows flip conditions” |

These are **not** golden for score, but not fail states.

---

## 4. Branch map & consequences

Each stop has 3 choices. **Only one continues the golden line.** Others jump to **side cars** or apply **modifiers**, then either rejoin, soft-lock, or require rewind.

### Notation

- `→ Gx` = go to golden stop  
- `→ Bx` = branch room  
- `Δ` = modifier (score, time, flags)  
- `↻` = can only recover via rewind  

### G1 TRIAGE

| Key | Choice | Consequence |
|-----|--------|-------------|
| 1 | Open Host Sweep | → **G2** · +data |
| 2 | Chase Large Uploads | → **B1 Noise warren** · +guess · spend +15s · then forced rejoin G1 with Host Sweep pre-highlighted or auto-advance to G2 with “distracted” flag |
| 3 | Isolate random host | → **B2 Blast door** · +act · **destructive attempt** · isolate **blocked** · flag `rash_act=true` · rejoin G2 with warning OR stay until rewind |

**B1 Noise warren (short):**  
Narration: upload FP demotions, scorer noise. One choice only: “Back to the #1 Host Sweep” → G2.  
*Consequence:* breadcrumb shows off-path triage; score “focus” penalty.

**B2 Blast door:**  
Narration: mutation denied / need evidence. Choices:  
1. **Rewind to triage** (Marty)  
2. **Stand down and open Host Sweep** → G2 with `rash_act`  
*Consequence:* ACT counter++; end badge “Almost broke the scene” if not rewound clean.

### G2 CASE

| Key | Choice | Consequence |
|-----|--------|-------------|
| 1 | Laptop DNS | → **G3** · +data |
| 2 | Lateral + isolate now | → **B3 Containment panic** · +act · destructive · tools “isolate” disabled rest of run unless rewind · must pick “stand down” to continue → G3 with `assumed_breach=true` |
| 3 | C2 / DNS tunnel escalate | → **B4 Theory car** · +guess · short dead-end theory · single exit “Test against remotes again” → G3 with `wild_theory=true` |

### G3 IDENTITY

| Key | Choice | Consequence |
|-----|--------|-------------|
| 1 | Normal Mac | → **G4** · +data |
| 2 | Quarantine (no agent = bad) | → **B5 Time-out trap** · +act · destructive · if `rash_act` already set, **harder lecture** · continue → G4 with `hostile_bias=true` |
| 3 | HR ticket from MAC | → **B6 People process** · state-changing · +act (process) · flag `named_human_error=true` → G4 |

### G4 TRAFFIC

| Key | Choice | Consequence |
|-----|--------|-------------|
| 1 | SaaS/MDM = FP | → **G5** · +data |
| 2 | Slack/Apple = C2 cover | → **B7 Tunnel vision** · +guess · if `wild_theory` or `hostile_bias`, show compounding error · forced “look at DNS list again” → G5 with lower confidence on endcard |
| 3 | Need another hour XQL | → **B8 Analysis paralysis** · +observe/stall · timer −20s or fake overtime · single continue → G5 |

### G5 TERMINUS (outcomes)

| Key | Outcome | Score hint |
|-----|---------|------------|
| 1 FP close | **Golden ending** if path mostly data & zero unresolved destructive | ★★★ |
| 2 Watch 24h | Silver ending | ★★ |
| 3 Flip conditions | Silver/learning ending | ★★ |

**Modifiers on endcard:**

| Flag | End text |
|------|----------|
| `rash_act` / any destructive pick not rewound | “You reached for containment early.” |
| `hostile_bias` | “You treated missing agent as guilt.” |
| `named_human_error` | “You almost blamed a person without a name.” |
| `wild_theory` | “You preferred a movie plot over public DNS.” |
| All golden | “Clean first pass — non-destructive until decide.” |

---

## 5. Marty McFly — rewind design

### Player mental model

> “I can jump back to an earlier station, change my choice, and the future from there rewrites — like a new timeline.”

### UX

1. **Path sidebar** = timeline (already started).  
2. Each past crumb gets **↩ Change this decision**.  
3. Confirm modal:  
   - *Rewrite future from here* (default) — drop all crumbs after that index; jump to that stop; clear flags introduced after.  
   - *Cancel*  
4. Optional later: **branch ribbon** “Timeline A / B” if we keep parallel saves (v2).

### State model (implement next)

```js
{
  timelineId: "t0",
  cursor: 2,                    // current beat index in graph
  nodeId: "G2",                 // graph node, not only linear index
  history: [                    // breadcrumbs / irreversible log until rewrite
    { nodeId: "G0", choiceKey: "1", move, integrity, stance, flagsDelta },
    { nodeId: "G1", choiceKey: "1", ... },
  ],
  flags: {
    rash_act: false,
    assumed_breach: false,
    hostile_bias: false,
    named_human_error: false,
    wild_theory: false,
    distracted: false,
  },
  scores: {
    data: 0,
    guess: 0,
    act: 0,
    goldenSteps: 0,
  },
  timer: { startedAt, durationSec: 180, penaltySec: 0 },
}
```

**Rewind to history index `i`:**

1. `history = history.slice(0, i)`  // keep the stop we’re redoing’s *previous* entries only  
2. Actually: if user clicks crumb for decision at step i, we remove i and after: `history = history.slice(0, i)`, set `nodeId = history[i-1].next` or start node for that crumb’s node, and re-open that node **without** the choice applied.  
3. Recompute `flags` and `scores` by replaying remaining history.  
4. Clear “future” branch rooms.  
5. Flash conductor line: *“Timeline rewritten from TRIAGE. Future stations unremembered.”*

### Rules

- Rewind is **always free** in training (no hard lock).  
- Optional: first rewind free, later rewinds cost 10s (still training-friendly).  
- Destructive attempts that were “blocked” still leave a **stain flag** unless rewound past them.  
- Golden path completion requires either never taking destructive stains or **rewinding them away**.

### Breadcrumb display after rewind

- Show rewritten path only (simple).  
- Optional ghost: faded “abandoned timeline” one-liner (v2).

---

## 6. Graph structure (implementation sketch)

Replace pure `beats[]` linear array with nodes:

```js
const NODES = {
  G0: { stop, room, lines, choices: {
    "1": { ...tags, next: "G1", golden: true },
    "2": { next: "G0", /* or B_meta */ golden: false },
    "3": { next: "G0", golden: false },
  }},
  G1: { choices: {
    "1": { next: "G2", golden: true },
    "2": { next: "B1", golden: false },
    "3": { next: "B2", golden: false },
  }},
  B1: { choices: { "1": { next: "G2", forceLabel: "Return to Host Sweep" } } }, // single or 3
  // ...
  G5: { terminal: true, choices: { ... endings } },
};
```

Side rooms **B\*** can have 1–3 choices; prefer **1 clear exit** for 3‑minute pacing, or 3 with two loops and one exit.

---

## 7. Scoring (simple enough for 3 minutes)

| Event | Score |
|-------|------:|
| Golden choice | +2 |
| Data stance | +1 |
| Guess stance | 0 |
| Act / destructive | −2 |
| Rewind past a stain | remove that stain’s −2 if replayed clean |
| Full golden no stain | badge **Clean first pass** |
| Finish with stains | badge **Messy but finished** |
| Finish after rewinds to golden | badge **Time traveler** |

Display on terminus + sidebar live counters (already have data/guess/act).

---

## 8. Conductor copy (tone)

- Golden: short affirm.  
- Guess: “Theory without crumbs…”  
- Act: “You reached for the blast door…”  
- Rewind: “Flux capacitor: back to {STOP}.”  

Keep MUD voice; keep ELI5 under every option; keep select→AI ELI5.

---

## 9. UX layout (target)

```
┌─────────────┬──────────────────────────────┐
│ YOUR PATH   │  MUD room + log + 3 choices  │
│ · crumbs    │  tags + ELI5 on each choice  │
│ · DATA/GUESS│                              │
│ · ACT count │                              │
│ · ↩ on past │                              │
└─────────────┴──────────────────────────────┘
```

Past crumb actions:

- **↩ Change decision** (Marty)  
- Hover: stance hint  

---

## 10. Implementation plan (next session)

### P0 — must ship ✅

1. ~~Refactor tour data from linear `beats[]` → **node graph** (`G*` + `B*`).~~  
2. ~~Wire choices to `next` node (real branches).~~  
3. ~~**Rewind** from breadcrumb (rewrite history, recompute flags).~~  
4. ~~Endings + flags on terminus.~~  
5. ~~Preserve: tags, choice ELI5, select ELI5, package load, stance counters.~~

### P1 — polish (partial)

1. ~~Time penalties on B-rooms.~~ (B1 +15s, B8 +20s)  
2. ~~“Time traveler” / “Clean first pass” badges.~~  
3. Abandoned timeline ghost line.  
4. ~~Keyboard: `R` open rewind to previous stop.~~

### P2 — later

1. Multiple packages selectable from hub.  
2. Persist best run in localStorage.  
3. Authoring: golden path + branches in package `path.json` / `mud-graph.json`.

---

## 11. Acceptance criteria

- [x] Golden run G0→G5 in ≤ ~3 minutes, zero destructive, badge Clean first pass.  
- [x] Choosing isolate enters consequence room; path crumb shows **ACT · Destructive**.  
- [x] From breadcrumb, user rewinds to TRIAGE, picks Host Sweep, flags clear if stain was after.  
- [x] Sidebar always reflects current timeline only (after rewrite).  
- [x] ELI5 select still receives full package + client path history (+ flags).  
- [x] No JS syntax regressions; :3106 loads; :3107 optional for AI ELI5.

---

## 12. Files to touch next

| File | Change |
|------|--------|
| `docs/mocks/06-shadow-hunter/index.html` | Graph, consequences, rewind UI |
| `docs/mocks/06-shadow-hunter/mud-graph.json` *(optional extract)* | Data-only graph for cleaner edits |
| `docs/mocks/06-shadow-hunter/eli5_server.py` | Optional: pass `history` / flags in client_context (already extensible) |
| `docs/mocks/docker-compose.mocks.yml` | Unchanged unless new service |
| This `handoff.md` | Update status when P0 done |

---

## 13. Open product decisions (resolve when implementing)

1. **Soft rejoin vs hard gate:** After isolate attempt, auto-continue with stain, or require explicit rewind?  
   - *Recommendation:* soft rejoin + stain (keeps 3‑min pace); rewind optional for clean badge.  
2. **Single exit branch rooms vs 3 choices:**  
   - *Recommendation:* B-rooms mostly **1 exit** + optional “rewind now”.  
3. **Does “FP resolve” count as state-changing forever?**  
   - *Yes* — teach Decide ≠ Destructive.  
4. **Timer:** pause on rewind modal?  
   - *Yes.*

---

## 14. One-paragraph summary for the next agent

Implement a **branching MUD** on the Shadow the Hunter mock (:3106) using the Host Sweep FP package. Encode a **golden path** G0–G5 (all non-destructive until Decide). Off-path choices go to short **consequence rooms** (noise, containment panic, theory, etc.) that set **flags** and stance (data/guess/act). Add **Marty McFly rewind** on breadcrumb items to truncate history and redo a decision. End with badges based on stains vs clean golden. Keep existing tags, ELI5, and AI select-explain. Details and tables are in this handoff.

---

*End of handoff — P0 complete; continue from §10 P1 residual (ghost timeline) or P2.*
