# Learning MUD V2 — research brief + journey design

**Journey:** Spike DNS Malware · Case 8612 (true positive)  
**Mock:** http://localhost:3108/  
**Package:** `docs/mocks/shadow-packages/sth-20260801-spike-dns-tp/`  
**Date:** 2026-08-01  

---

## 1. Why a MUD for threat-hunt training

MUDs and interactive fiction work for learning when they treat the player as a **problem-solver in a world**, not a quiz-taker. Research on educational games and narrative learning points to the same few levers:

| Principle | Source tradition | How we apply it |
|-----------|------------------|-----------------|
| **Learning objective per beat** | Gagné / instructional design | Each stop states a skill (“Filter noise”, not “Pick option 1”) |
| **Deliberate practice** | Ericsson | One hard skill at a time; golden path is the known-good procedure |
| **Productive failure** | Kapur; exploratory learning | Off-path rooms are short, honest, and teach *why* it failed |
| **Safe failure + retry** | Growth mindset; serious games | Marty rewind rewrites timeline without shame |
| **Immediate feedback** | Games + tutoring systems | Conductor reply in seconds; stance tags (data/guess/act) |
| **Scaffold then fade** | Vygotsky ZPD | ELI5 under choices; jargon tips; optional AI select-ELI5 |
| **Reflection / debrief** | Kolb experiential cycle | Terminus asks “what skill did you prove?” + skill scoreboard |
| **Transfer** | Near/far transfer research | Contrast FP (Host Sweep tour) vs TP (this tour) in same venue |
| **Mastery over points** | Competency-based education | Badges = skills demonstrated, not only path purity |
| **Agency with rails** | Interactive narrative design | Branches real; golden path still completable in ~4 minutes |

### What *not* to do (common serious-game failures)

1. **Trivia disguised as story** — if every wrong answer just says “try again” with no new room, it’s a quiz.  
2. **Punishment without teaching** — traps that waste time without a concept.  
3. **Score as the only reward** — juniors optimize the meter, not the method.  
4. **Spoilers as the only coach** — always show *why*, not only the answer key.  
5. **No recovery** — dead ends that force restart kill experimentation.  

---

## 2. End goal for this experience

After one clean run (and ideally one messy run + rewind), the learner should be able to:

1. **Filter** a noisy “new” queue and still find a live TP in *under_investigation*.  
2. **Read** a Spike DNS Malware case without confusing the **Umbrella VA** with C2.  
3. **Scope** a domain IoC: sole-source host + hit volume.  
4. **Identify** an agentless NOC Wi‑Fi Mac without inventing guilt or HR drama.  
5. **Corroborate** multi-source (case + enrich + identity + XQL) and accept **TI + volume** when IPS has no malware signature.  
6. **Decide** *malicious true positive* with residual uncertainty, and list **human** next steps (ownership, block/watch domain, no reckless auto-isolate).

**Not the goal:** memorizing case 8612 IDs or punishing people on NOC Wi‑Fi.

---

## 3. Journey story (evidence-backed)

**Headline:** Live true positive — Spike DNS Malware → `{{DOMAIN_IOC}}`  
**Case:** {{CASE_PRIMARY}} · severity medium · category Exfiltration · starred  
**Shape:** Sole internal source **{{HOST_A}}** · ~697 DNS hits / 72h · resolver **{{DNS_VA}}** (venue OpenDNS/Umbrella)  
**Host:** Agentless Mac · mDNS **{{HOSTNAME_A}}** · NOC WiFi VLAN · operator-shaped SaaS (Slack/Anthropic/Keybase/VS Code)  
**Detection:** DNS volume + multi-vendor malware domain intel — **not** an IPS malware hit on the domain  
**Disposition:** malicious_true_positive · high priority on NOC segment · human ownership still open  

**Contrast (optional later gold):** Case 8016 dual-RAT historical — closed path, zero live C2 now.

---

## 4. Golden path (skills)

| ID | Stop | Skill | Golden move | Integrity |
|----|------|-------|-------------|-----------|
| G0 | STATION | META | Board the TP hunt | ND |
| G1 | TRIAGE | **FILTER** | Skip critical ZGrab / Large Upload noise; open under_investigation malware DNS | ND |
| G2 | CASE | **READ** | Spike DNS → domain IoC; traffic is host→DNS VA :53 | ND |
| G3 | ENRICH | **SCOPE** | Sole-source domain: one host, hundreds of hits | ND |
| G4 | IDENTITY | **ID** | Agentless NOC Mac; thin telemetry ≠ “not real” | ND |
| G5 | TRAFFIC | **CORROBORATE** | Beacon-shaped DNS to resolver; TI holds; no IPS domain sig | ND |
| G6 | TERMINUS | **DECIDE** | TP close + human actions; no auto-isolate agentless | State-changing (ticket) |

**Golden integrity signature:** ND ×6 then state-changing Decide (ticket/process — not host destroy).

---

## 5. Consequence rooms (productive failure)

| Branch | Trigger | Teaches | Flag |
|--------|---------|---------|------|
| B1 Scanner warren | Open Exchange RCE / ZGrab #1 | Critical severity ≠ internal TP | `noise_chase` |
| B2 Upload fog | Chase Large Upload volume | Venue upload FP class | `volume_bias` |
| B3 Blast door | Isolate host immediately | Agentless + ownership first | `rash_act` |
| B4 Sinkhole shrug | “Umbrella blocked it, ignore” | Blocked DNS can still mean infected host | `under_react` |
| B5 Name-and-shame | Public blame from mDNS | Confirm owner in private channel | `named_without_confirm` |
| B6 Auto-resolve | Close without human | Mutations need ownership | `process_skip` |
| B7 Gold museum | Only hunt closed 8016 | Live queue still needs live TPs | `history_only` |
| B8 Paralysis | Another hour of XQL | Enough multi-source to decide | `stall` |

Recovery: soft rejoin with stain **or** Marty rewind (free in training).

---

## 6. Pedagogy UI (V2 deltas vs mock 06)

| V1 (06 Host Sweep FP) | V2 (07 Spike DNS TP) |
|------------------------|----------------------|
| Stance: data / guess / act | + **Skills** strip (FILTER…DECIDE) |
| Conductor flavor | Explicit **Learn:** line per stop |
| End badges path-purity | Badges = **skills clean** + optional path purity |
| Teaching moral: don’t isolate FP | Teaching moral: **do** escalate TP, still human-safe |
| Rails→branching | Same graph engine; more reflection at terminus |

---

## 7. Privacy (training package)

| Real | Token / policy |
|------|----------------|
| Case 8612 | `{{CASE_PRIMARY}}` in package; UI may show case # for realism in mock |
| `10.220.251.89` | `{{HOST_A}}` in package; mock shows token or demo IP consistently |
| Person / mDNS personal name | **Redact** → `{{OWNER_HINT}}` / hostname token |
| Assignee email | Operator map only — never learner UI |
| `epicunitscan.info` | Keep (public malware IoC) or `{{DOMAIN_IOC}}` |
| `172.16.16.16` | `{{DNS_VA}}` |

Operator-only: `redaction-map.json` (gitignored pattern).

---

## 8. Success metrics (for authors)

- Golden run ≤ ~4 minutes.  
- After one off-path isolate attempt + rewind, learner can state agentless constraint.  
- At terminus, learner lists ≥2 human actions (owner confirm + domain block/watch).  
- Contrast question: “How is this different from Host Sweep → public DNS FP?”  

---

## 9. References (practice-facing, not academic dump)

- Interactive fiction / educational games: agency, feedback loops, meaningful choices.  
- Deliberate practice: focused skill, immediate feedback, progressive difficulty.  
- Productive failure: struggle → structure → consolidate.  
- Experiential learning: experience → reflect → conceptualize → apply.  
- Shadow the Hunter design: method over answers; multi-source; no PII to external LLMs.

---

*Build implements this brief in mock 07 + package `sth-20260801-spike-dns-tp`.*
