# Shadow the Hunter — Product & Technical Design

**Status:** Draft for review  
**Platform:** NOCgentic (Black Hat NOC / AI SOC)  
**Date:** August 2026  
**Related:** UX mocks (`docs/mocks/`), CLAUDE.md security principles (“No PII to external LLMs”)

---

## 1. One-paragraph product definition

**Shadow the Hunter** sources real completed Black Hat threat hunts into NOCgentic and turns them into guided learning paths that follow the “known good” investigation flow. Learners walk through an actual past hunt step-by-step so they can see what strong threat hunting looks like in practice. They still have the freedom to ask open questions and explore, and they can toggle the original hunter’s reasoning and findings on or off as a reference whenever they want.

---

## 2. Goals and non-goals

### 2.1 Goals

| Goal | Success looks like |
|------|--------------------|
| Teach method, not just answers | Learners can restate *why* each step was taken |
| Preserve free exploration | Off-path questions still hit real (or replay) data tools |
| Optional answer key | Hunter panel OFF by default for practice; ON for coaching |
| Safe to show at conference / training | Learner-facing packages contain **no raw PII** and minimal re-identifiable content |
| Fit existing stack | Paths drive orchestrator intents / agents; no parallel “toy” backend as source of truth |

### 2.2 Non-goals (MVP)

- Real-time multiplayer “same hunt” collaboration  
- Auto-grading that claims ground-truth correctness on live networks  
- Uploading *live* ongoing incidents as learning paths (completed hunts only)  
- Guaranteeing that every freeform detour returns the same rows the original hunter saw years later (data ages out; see §9)

---

## 3. Personas and modes

| Persona | Needs |
|---------|--------|
| **Learner** (attendee, junior analyst) | Clear next step, freedom to ask, optional mentor voice |
| **Author** (original hunter / NOC staff) | Export a completed hunt without leaking people or secrets |
| **Curator / reviewer** | Approve packages only after automated + human privacy gates |
| **Operator** (platform admin) | Revoke a path, rotate redaction maps, audit who saw what |

**Learner modes**

1. **Guided path** — step rail advances with suggested actions  
2. **Free explore** — open chat/query against allowed data scope for that path  
3. **Shadow ON** — original hunter reasoning + findings visible  
4. **Shadow OFF** — same path/steps without spoilers (practice / assessment)

---

## 4. Experience design (runtime)

### 4.1 Layout (conceptual)

```
┌──────────────────────────────────────────────────────────────────┐
│ PATH: “Scan + S3 threshold · BH sample 2026-07-31”   Step 2/6    │
│ [Shadow: OFF ░░░░░]  [Show original hunter]                      │
├───────────────┬────────────────────────────┬─────────────────────┤
│ STEP RAIL     │ LEARNER WORKSPACE          │ SHADOW PANEL        │
│ 1 Recon       │ Chat / suggested actions   │ (hidden if OFF)     │
│ 2 Correlate ● │ Evidence pins              │ Reasoning           │
│ 3 Decide      │ Tool results (sanitized)   │ Key findings        │
│ 4 Report      │                            │ “What I checked”    │
└───────────────┴────────────────────────────┴─────────────────────┘
```

### 4.2 Step lifecycle

For each path step the system exposes:

| Field | Learner sees | Shadow panel (if ON) |
|-------|--------------|----------------------|
| Objective | “What to accomplish in this step” | Same + *why the hunter chose this order* |
| Suggested action | Button / intent template | Exact original query text (redacted) |
| Expected evidence types | e.g. notice, conn, dns | Which tables/sources were used |
| Success criteria (soft) | “You have at least one host pinned” | Original IOC set (tokenized) |
| Findings | — until Shadow ON or step complete | Hunter write-up for this step |

**Advance rules (MVP):** learner may skip ahead; soft gates only (warn if inventory empty). Hard gates optional for training assessments later.

### 4.3 Free exploration vs path scope

- Free questions stay inside a **data scope** declared by the package (`data_scope`).  
- Scope may be: time window, table allow-list, host/token allow-list, demo sample ID.  
- Out-of-scope asks return a clear message: *“This path’s data window doesn’t include that; try … or leave the path.”*

---

## 5. Threat hunt package format

Uploads are not free-form Word docs. Authors produce a **Hunt Package** — a versioned, machine-validated archive.

### 5.1 Package container

```
hunt-package/
  manifest.json          # required — schema + metadata + privacy attestation
  path.json              # required — ordered steps + objectives
  shadow.json            # required — original hunter reasoning (may be empty objects)
  evidence/              # optional — redacted excerpts only
    step-01.json
    step-02.json
  artifacts/             # optional — final report (Markdown, already redacted)
    final-report.md
  redaction-map.json     # required for publish — token ↔ original (SERVER-ONLY; never to learners)
  checksums.sha256       # required
```

**Delivery options**

| Option | Use |
|--------|-----|
| **`.hunt.zip`** | Human authoring / offline review (contains everything except secrets) |
| **API JSON** | CI / export from an internal after-action tool |
| **Split publish** | `redaction-map.json` stored only in a private vault; learner blob has tokens only |

**Rule:** Anything under learner-readable storage must be **publish-safe**. The redaction map never ships to the browser.

### 5.2 `manifest.json` (required)

```json
{
  "schema_version": "1.0.0",
  "package_id": "sth-2026-07-31-scan-s3-001",
  "title": "Address scan and S3 volume threshold",
  "subtitle": "Recon vs hygiene: picking the sharp signal",
  "event": {
    "name": "Black Hat USA 2026 NOC",
    "edition": "usa-2026"
  },
  "time_scope": {
    "timezone": "UTC",
    "window_start": "2026-07-31T00:00:00Z",
    "window_end": "2026-07-31T23:59:59Z",
    "note": "Bound to demo sample / redated partition; not live attendee traffic"
  },
  "data_scope": {
    "mode": "sample_or_athena",
    "sample_id": "local-sample-2026-07-31",
    "athena": {
      "database": "blackhatnoc_glue",
      "tables_allow": ["notice", "suricata_corelight", "conn", "dns", "ssl"],
      "partition_hint": "dt=2026-07-31"
    }
  },
  "difficulty": "intermediate",
  "estimated_minutes": 25,
  "tags": ["recon", "scan", "exfil", "ssl-noise"],
  "authors": [
    {
      "role": "original_hunter",
      "display_name": "NOC Analyst A",
      "identity_ref": "staff:redacted"
    }
  ],
  "privacy": {
    "classification": "training-safe",
    "contains_pii": false,
    "sanitizer_version": "sth-sanitize/1.0.0",
    "sanitized_at": "2026-08-01T12:00:00Z",
    "reviewer": "staff:curator-1",
    "review_status": "approved",
    "attestation": "I confirm raw personal data was not included; IPs/domains tokenized per policy."
  },
  "created_at": "2026-08-01T12:00:00Z",
  "content_hash": "sha256:…"
}
```

### 5.3 `path.json` — known-good flow (required)

```json
{
  "schema_version": "1.0.0",
  "primary_question": "What is the most credible threat in this window, and what evidence supports it?",
  "steps": [
    {
      "id": "step-01-recon",
      "order": 1,
      "title": "Triage high-interest notices",
      "learner_objective": "List sparse high-severity signals before drowning in cert volume.",
      "suggested_actions": [
        {
          "type": "agent_intent",
          "agent": "alert-triage",
          "template": "Show high-interest notices and scans in the path time window",
          "params": { "time_range_hours": 24, "focus": "high_severity" }
        }
      ],
      "evidence_types": ["notice", "suricata"],
      "soft_success": {
        "min_pins": 1,
        "pin_kinds": ["host", "signal"]
      },
      "hints_learner_safe": [
        "Volume leaders are not always the incident.",
        "Look for Scan:: and Exfil:: style notices."
      ]
    },
    {
      "id": "step-02-correlate",
      "order": 2,
      "title": "Correlate hosts in conn / dns",
      "learner_objective": "Check whether pinned hosts appear as top talkers or rare outliers.",
      "suggested_actions": [
        {
          "type": "agent_intent",
          "agent": "athena-hunter",
          "template": "Top source hosts by bytes and connection count in the window"
        }
      ],
      "evidence_types": ["conn", "dns"],
      "soft_success": { "min_pins": 2 }
    },
    {
      "id": "step-03-decide",
      "order": 3,
      "title": "Declare primary vs secondary leads",
      "learner_objective": "Pick one primary narrative and one secondary watch item.",
      "suggested_actions": [
        { "type": "workspace", "template": "Write a one-paragraph disposition" }
      ],
      "evidence_types": []
    },
    {
      "id": "step-04-report",
      "order": 4,
      "title": "File the case narrative",
      "learner_objective": "Produce a short report a NOC lead could act on.",
      "suggested_actions": [
        { "type": "workspace", "template": "Summarize decision, evidence, next steps" }
      ]
    }
  ]
}
```

### 5.4 `shadow.json` — original hunter (required; shown only when Shadow ON)

```json
{
  "schema_version": "1.0.0",
  "hunter_display_name": "NOC Analyst A",
  "overall_reasoning": "Cert failures dominated volume; I prioritized sparse high-impact notices first (scan, S3 threshold), then used conn only to sanity-check whether those hosts were also top talkers in the partial extract.",
  "final_findings": [
    {
      "severity": "high",
      "summary": "Primary: address scan from host {{HOST_A}} (≥249 hosts, 443/8900, ~6m).",
      "entities": ["{{HOST_A}}"]
    },
    {
      "severity": "medium",
      "summary": "Secondary: S3 volume threshold on {{HOST_B}}; needs full-day byte confirmation.",
      "entities": ["{{HOST_B}}"]
    }
  ],
  "steps": {
    "step-01-recon": {
      "reasoning": "I ignored raw volume and listed non-SSL notices first.",
      "original_queries": [
        {
          "tool": "athena",
          "description": "Group notice.note counts for window",
          "redacted_sql_or_nl": "SELECT note, count(*) FROM notice WHERE dt = '{{DT}}' GROUP BY 1"
        }
      ],
      "findings": [
        "Scan::Address_Scan on {{HOST_A}}",
        "AWSStorageExfil on {{HOST_B}}"
      ],
      "entities": ["{{HOST_A}}", "{{HOST_B}}"]
    },
    "step-02-correlate": {
      "reasoning": "{{HOST_INFRA}} dominated conn counts — treated as infra noise, not the lead.",
      "original_queries": [],
      "findings": ["{{HOST_A}} not in top-bytes sample; still valid via notice text"],
      "entities": ["{{HOST_INFRA}}", "{{HOST_A}}"]
    }
  }
}
```

**Convention:** All network/user identifiers in learner-facing JSON are **tokens** (`{{HOST_A}}`), not bare addresses, emails, or names. Resolution for display uses a **session display map** (token → synthetic label like `host-alpha.lab`) never the original employee identity.

### 5.5 `evidence/step-NN.json` (optional, redacted excerpts)

```json
{
  "step_id": "step-01-recon",
  "rows": [
    {
      "source": "notice",
      "ts": "2026-07-31T19:54:46Z",
      "fields": {
        "note": "Scan::Address_Scan",
        "msg": "{{HOST_A}} scanned at least 249 unique hosts on ports 443/tcp, 8900/tcp in 6m",
        "id_orig_h": "{{HOST_A}}"
      }
    }
  ],
  "row_limit": 50,
  "note": "Excerpts only; not a full table dump"
}
```

### 5.6 `redaction-map.json` (server-only)

```json
{
  "schema_version": "1.0.0",
  "package_id": "sth-2026-07-31-scan-s3-001",
  "algorithm": "hmac-sha256",
  "key_id": "sth-redact-key-2026-q3",
  "entries": [
    { "token": "{{HOST_A}}", "kind": "ip", "original_hash": "sha256:…", "display_label": "host-scan-01" },
    { "token": "{{HOST_B}}", "kind": "ip", "original_hash": "sha256:…", "display_label": "host-s3-01" },
    { "token": "{{HOST_INFRA}}", "kind": "ip", "original_hash": "sha256:…", "display_label": "host-infra-dns" }
  ]
}
```

- Store in **Secrets Manager / private S3 prefix**, IAM-restricted to upload + rehydrate jobs.  
- **Never** embed in the web bundle or learner API responses.  
- Prefer **hash of original** over storing plaintext originals when rehydration is not required. If operators need reverse lookup for legal hold, keep plaintext in a higher-tier vault with break-glass audit.

### 5.7 JSON Schema & validation

Publish rejects the package unless:

1. `schema_version` supported  
2. `path.steps` non-empty, unique `id`s, contiguous `order`  
3. Every `shadow.steps` key ⊆ path step ids  
4. Privacy scanner passes (§6)  
5. No raw match for blocked patterns in any learner-facing file  
6. `checksums.sha256` matches all files  
7. `privacy.review_status == approved` for public/training visibility  

---

## 6. Ensuring no PII is shared

PII control is **defense in depth**: format constraints → automated sanitizer → human review → runtime filters → LLM boundary → audit.

### 6.1 What we treat as sensitive (training policy)

| Category | Examples | Training policy |
|----------|----------|-----------------|
| **Direct identifiers** | Person name, email, phone, badge ID, employer HR ID | **Strip or refuse publish** |
| **Account identifiers** | Personal IAM user ARNs tied to humans, Slack handles, GitHub logins | Tokenize or remove |
| **Auth material** | Passwords, tokens, cookies, private keys, session IDs | **Hard block** — never in package |
| **Message content** | Email subjects/bodies, chat snippets with people | Strip; keep only technical IOC narrative |
| **High-risk free text** | Hunter notes naming people (“talked to Jane in booth ops”) | Redact to roles (“booth ops contact”) |
| **Network identifiers** | Internal IPs, MACs, hostnames with usernames | **Tokenize** (not always deleted — needed to teach pivots) |
| **Org-sensitive** | Unreleased vuln titles, customer names, non-public vendor tickets | Policy flag; curator decision |
| **Attendee / badge data** | Anything from registration systems | **Out of scope forever** for hunt packages |

SOC training inevitably uses IPs and domains. Those are **not classic PII** but can be **re-identifying** in a small environment. Policy: **pseudonymize by default** for anything learner-facing.

### 6.2 Upload pipeline (privacy gates)

```
 Author draft (may contain raw IOCs)
        │
        ▼
 ┌──────────────────┐
 │ 1. Ingest parse  │  unzip + schema validate
 └────────┬─────────┘
          ▼
 ┌──────────────────┐
 │ 2. Auto-sanitize │  sth-sanitize (deterministic)
 │    - pattern PII │
 │    - IP/host map │
 │    - secret scan │
 └────────┬─────────┘
          ▼
 ┌──────────────────┐
 │ 3. Scanner report│  fail / warn / pass
 └────────┬─────────┘
          ▼
 ┌──────────────────┐
 │ 4. Human review  │  curator checklist + diff of redactions
 └────────┬─────────┘
          ▼
 ┌──────────────────┐
 │ 5. Split store   │  publish-safe blob  vs  redaction-map vault
 └────────┬─────────┘
          ▼
     Learner-visible path catalog
```

**Failed sanitizer or unapproved review ⇒ package is not listable in UI.**

### 6.3 Sanitizer rules (deterministic)

Implement as `tools/sth-sanitize` (or `packages/shared` module) with a **versioned rule pack**.

| Rule ID | Action |
|---------|--------|
| `PII_EMAIL` | Replace with `{{EMAIL_n}}` or delete field |
| `PII_PHONE` | Delete |
| `PII_PERSON_NAME` | Heuristic + denylist of staff names from upload form → `{{PERSON_n}}` |
| `SECRET_KEY` | Fail package (API keys, `BEGIN PRIVATE KEY`, JWT-like, AWS AKIA…) |
| `IP_V4` / `IP_V6` | Map to stable token via HMAC(ip, key_id) → `{{HOST_xx}}` |
| `MAC` | Tokenize |
| `HOSTNAME` | Tokenize if matches user-like patterns (`jsmith-mbp`) |
| `URL_USERINFO` | Strip userinfo from URLs |
| `HEADER_COOKIE` | Delete |
| `LONG_FREE_TEXT` | Run pattern suite; optional LLM **only after** pattern pass and only on already-tokenized text |

Stable HMAC tokenization ensures the same IP becomes the same token across steps (pivots still work).

### 6.4 Authoring requirements (process)

Authors must:

1. Export from **after-action notes**, not raw ticket dumps with people tagged.  
2. Run local `sth-sanitize --check` before upload (same rules as server).  
3. Sign `privacy.attestation` in manifest.  
4. Prefer technical entities (note names, ports, techniques) over narrative gossip.  
5. Never paste credentials “for context.”

### 6.5 Runtime enforcement (after publish)

| Layer | Control |
|-------|---------|
| **API** | Learner endpoints serve only `training-safe` packages; strip `redaction-map` |
| **Shadow panel** | Content is already tokenized; no reverse lookup in browser |
| **Agent / Athena queries** | Bound by `data_scope`; results pass **output sanitizer** before UI/LLM |
| **LLM boundary** | Existing principle: sanitize prompts; never send emails, names, raw cookies; prefer tokens already in path |
| **Free explore** | Same output sanitizer; block queries outside allow-listed tables/window |
| **Logs / traces** | Audit-monitor / OTEL: hash queries; do not log full row payloads with pre-redaction values |
| **Exports** | “Download my notes” export re-runs sanitizer |

### 6.6 What the learner UI is allowed to show

| Allowed | Not allowed |
|---------|-------------|
| Tokenized hosts (`host-scan-01` / `{{HOST_A}}`) | Real badge names, emails |
| Alert/note types, ports, counts, timestamps (in scope) | Auth tokens, cookies, private keys |
| Redacted hunter reasoning | Unredacted chat with people named |
| Synthetic display labels | Original reverse map |

### 6.7 Residual risk & acceptance

- **Re-identification via rare event timing** remains possible for insiders who were on shift. Mitigation: coarse timestamps if needed (`~19:00 UTC`), delay publish until after event, limit distribution to training tenants.  
- **Automated name detection is imperfect.** Mitigation: mandatory human review for v1.  
- **Live Athena in explore mode** might return raw IPs from the warehouse. Mitigation: either (a) explore only against **pre-redacted sample tables**, or (b) force **result-set tokenization** with the package key before render. **MVP recommendation: (a)** — bind Shadow paths to curated samples / redated demo partitions already used for demos.

---

## 7. System architecture (how it fits NOCgentic)

```
                    ┌─────────────────────────────┐
                    │  Web UI · Shadow the Hunter │
                    │  path rail · chat · toggle  │
                    └──────────────┬──────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │  web-server                 │
                    │  /api/v1/shadow/paths       │
                    │  /api/v1/shadow/paths/:id   │
                    │  /api/v1/shadow/.../step    │
                    │  reuses /api/v1/chat        │
                    └──────┬─────────────┬────────┘
                           │             │
              publish-safe │             │ chat with path context
              packages     │             │
                    ┌──────▼──────┐ ┌────▼────────────┐
                    │ Object store│ │ Orchestrator    │
                    │ (S3)        │ │ + agents        │
                    └──────▲──────┘ └─────────────────┘
                           │
              ┌────────────┴────────────┐
              │ Upload service          │
              │ sanitize → review → split│
              └────────────▲────────────┘
                           │
                     Author upload
```

### 7.1 Suggested APIs (MVP)

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/shadow/paths` | List approved training-safe paths |
| `GET` | `/api/v1/shadow/paths/:id` | Manifest + path (no redaction map) |
| `GET` | `/api/v1/shadow/paths/:id/shadow` | Hunter panel payload (still tokenized) |
| `POST` | `/api/v1/shadow/paths/:id/session` | Start learner session (mode, shadow default off) |
| `POST` | `/api/v1/chat` | Existing chat; body gains optional `shadowSessionId` for scope |
| `POST` | `/api/v1/admin/shadow/packages` | Upload (auth’d staff) |
| `POST` | `/api/v1/admin/shadow/packages/:id/approve` | Curator approve |

### 7.2 Session object (server)

```json
{
  "session_id": "…",
  "package_id": "sth-…",
  "shadow_enabled": false,
  "current_step_id": "step-01-recon",
  "pins": [],
  "data_scope": { "…from manifest…" },
  "started_at": "…"
}
```

When `shadowSessionId` is present on chat, orchestrator receives **scope constraints** and a system preamble: *learner is on step X; do not reveal shadow findings unless shadow_enabled*.

---

## 8. Authoring workflow

1. Hunter completes a real investigation (prod tools / Athena).  
2. After-action: write steps + reasoning in the package template (or export tool).  
3. Local `sth-sanitize --in raw/ --out safe/`.  
4. Upload `.hunt.zip` via admin UI.  
5. CI/server re-sanitizes and produces scanner report.  
6. Curator reviews report + Shadow text; approves.  
7. Package appears in learner catalog.  
8. Optional: bind `data_scope.sample_id` to the local-sample / redated partition used for demos.

---

## 9. Data freshness and fidelity

| Problem | Approach |
|---------|----------|
| Original Athena day ages out | Package carries **evidence excerpts** for offline steps; explore mode uses demo sample with same *shape* |
| Live data ≠ original day | UI labels path as **Replay / Training sample**, not “live truth” |
| Learner free ask returns different rows | Expected; scoring is methodological, not byte-identical |

---

## 10. MVP scope vs later

### MVP

- Package schema `1.0.0` + validator  
- Admin upload + sanitize + manual approve  
- Learner path UI: step rail, suggested actions, free chat with scope, Shadow toggle  
- 1–3 hand-authored packages from real BH hunts (or high-quality reconstructions on local-sample)  
- Explore bound to **curated sample / demo partition** only  

### Later

- Export from after-action tooling with one click  
- Result-set tokenization against live Athena  
- Assessment mode (Shadow locked OFF, rubric)  
- Multi-language  
- Branching “wrong turn” annotations  

---

## 11. Security & compliance checklist (publish gate)

- [ ] No emails, phones, person names in learner files  
- [ ] No secrets (gitleaks-class patterns)  
- [ ] IPs/hostnames tokenized; map not in learner blob  
- [ ] Shadow text reviewed for interpersonal/PII narrative  
- [ ] `data_scope` does not point at production attendee PII stores  
- [ ] Package classification `training-safe`  
- [ ] Curator approval recorded with timestamp + identity  
- [ ] Content hash stored for integrity  
- [ ] Revocation path tested (unlist package)  

---

## 12. Open decisions

1. **Token display:** show `{{HOST_A}}` vs friendly `host-scan-01`? (Recommendation: friendly labels in UI, tokens in JSON.)  
2. **Who may upload?** NOC staff only vs broader BH content team.  
3. **Retention:** how long after an event are paths kept?  
4. **Legal:** training data license / attendee agreement language for replayed NOC telemetry.  
5. **Live vs sample explore** for MVP (this design recommends sample-only).  

---

## 13. Appendix A — Minimal valid package (sketch)

A minimal package can omit `evidence/` if every step’s suggested action can run against `data_scope` alone. It still **must** include `manifest.json`, `path.json`, `shadow.json`, `redaction-map.json` (vault), and checksums.

## 14. Appendix B — Alignment with current mocks

| Mock | Role in Shadow the Hunter |
|------|---------------------------|
| Quest board | Catalog of paths (“accept this hunt”) |
| Dungeon / steps | Step rail = known-good flow |
| Ghost guide | Shadow panel = *specific* original hunter, toggleable |
| IF console | Free explore language |
| Mission tree | Optional curated “start here” for first-time learners |

---

## 15. Next implementation slices (when approved)

1. Freeze `schema_version` `1.0.0` as JSON Schema files under `docs/shadow-schema/`.  
2. Implement `sth-sanitize` + CI check.  
3. Build one gold package from local-sample (stand-in completed hunt).  
4. Mid-fi UI mock on port 3106: path + free ask + Shadow toggle.  
5. Wire admin upload behind existing staff auth patterns.

---

*End of design draft.*
