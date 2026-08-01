# Handoff — Spike DNS TP Learning MUD V2

**Date:** 2026-08-01  
**Status:** V2 mock + package shipped  
**Live:** http://localhost:3108/  
**Package:** `docs/mocks/shadow-packages/sth-20260801-spike-dns-tp/`  
**Research/design:** `LEARNING-MUD-V2.md`  
**Source inv:** `inv_20260801_151132_6816b3` · case **8612** TP  

---

## What shipped

1. **Learning brief** — MUD/IF pedagogy → skill-per-stop, productive failure, rewind, reflection  
2. **Hunt package** — tokenized evidence + path.json skills + hunter narrative  
3. **Mock 07** — branching graph G0–G6 + B rooms, skill strip, debrief reflection  
4. **Compose** — port **3108** · hub card  

## Golden path

FILTER → READ → SCOPE → ID → CORROBORATE → DECIDE  
All choice **1** after board → badge **Method locked in**

## Contrast

FP tour remains :3106 (`sth-20260801-host-sweep-fp`). Same method, opposite disposition.

## Privacy

- Person names / assignee redacted in package  
- `redaction-map.json` operator-only (not in mock `package/` copy)  
- mDNS personal name → `operator-macbook.local` token in UI  

## Optional next (P1)

- Wire mock-07 to ELI5 with package context (clone 06 eli5)  
- Optional gold car deeper on 8016 dual-RAT  
- Extract `mud-graph.json` for authoring  
- localStorage best skill score  

## Acceptance

- [x] Research brief with learn/grow end goal  
- [x] Package from 8612 review order  
- [x] Branching MUD with skills + rewind + reflection  
- [x] Hub + compose  

*Run:* `docker compose -f docs/mocks/docker-compose.mocks.yml up -d mock-07-spike-dns-tp mock-hub`  
