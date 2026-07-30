# SLICE 6 — Proactive threat-hunting scheduler (level9000)

## Contract
- **Goal:** The platform hunts on its own: a registry of MITRE-mapped hunt templates (NL hunt
  questions, since the investigator does NL→SQL) that a scheduler runs on an interval, each hunt
  invoking the investigator loop and filing a finding tagged with its MITRE technique — so threats
  surface without an analyst asking. Delivers "Proactive Threat Hunting" + "24/7 hunt".
- **Acceptance (observable, via API + unit):**
  1. Hunt registry: a set of built-in hunt templates, each {id, name, mitre_tactic, mitre_technique,
     hypothesis, hunt_query (NL), enabled, interval_hours}. `GET /hunts` lists them.
  2. `POST /hunts/{id}/run` → runs the hunt NOW: calls the investigator with the hunt_query, stores a
     `hunt_run` row linking the hunt to the investigation run_id + the finding, tagged with the MITRE
     technique. Returns {hunt_run_id, investigation_run_id, finding}.
  3. `GET /hunts/runs?hunt_id=&since=` → recent hunt runs (finding summary + verdict + mitre tag + run_id).
  4. Scheduler: a tick function `due_hunts(now)` (CODE, deterministic) returns hunts whose
     last_run + interval_hours <= now (or never-run + enabled). Unit-tested with injected clock — NO
     real timer in tests. The service runs a background loop calling this on an interval, but the
     DECISION of what's due is pure/testable.
  4b. Only ENABLED hunts run; a disabled hunt is never due. `POST /hunts/{id}/enable|disable` toggles.
  5. Findings from hunts flow into the SAME store (reuse agent_runs/agent_events via the investigator;
     add a `hunt_runs` table linking hunt_id → investigation run_id + verdict + mitre + created_at).
  6. Data/voice split: the investigator (already code-owns facts) does the hunt; the scheduler is pure
     orchestration + timing. No new LLM calls in the scheduler itself.
- **Done:** acid green from clean (test_hunts.py: registry, due_hunts clock logic, run flow with a fake
  investigator client, enable/disable). Container smoke.

## Architecture — new `hunter` service (:8010), reuses store + calls investigator
- Built-in hunt templates in `agents/hunter/hunt_templates.py` (a Python list of dicts) — hand-authored,
  MITRE-tagged, NL hunt questions grounded in the Corelight/Suricata Athena schema. Seed ~6 across
  tactics (initial-access, C2, lateral-movement, exfil, discovery, persistence). Derived in SPIRIT from
  virtual_resident schema/th-guide.json (9 MITRE tactics) but expressed as NL (the investigator does
  NL→SQL; the CQL in th-guide is LogScale, not Athena, so we do NOT port the raw queries).
- New migration `agents/shared/migrations/0003_hunts.sql`: `hunts` (id, name, mitre_tactic,
  mitre_technique, hypothesis, hunt_query, enabled bool, interval_hours int, last_run_at, created_at)
  + `hunt_runs` (id, hunt_id, investigation_run_id, verdict, severity, mitre_technique, summary,
  created_at). Seeded from hunt_templates on init (idempotent upsert by a stable hunt id = slug).
- store.py additions: register_hunts(templates), list_hunts(), get_hunt(id), set_hunt_enabled(id,bool),
  mark_hunt_ran(id, ts), due_hunts(now) [PURE selection over enabled + last_run_at + interval],
  record_hunt_run(...), list_hunt_runs(hunt_id?, since?).
- `agents/hunter/main.py` (FastAPI :8010): endpoints above + a background scheduler task (asyncio)
  that every SCHED_TICK_SECONDS calls due_hunts(now) and runs each via the InvestigatorClient seam
  (same HttpInvestigatorClient pattern as triage; injectable Fake for tests). Guard: scheduler loop is
  best-effort, logs failures, never crashes the service. Disable the auto-loop in tests (env HUNTER_AUTORUN=0).

## Tests — tests/python/test_hunts.py (PG skip-guard, Fake investigator client, injected clock)
- registry seeded on init; list_hunts returns built-ins; get_hunt.
- due_hunts(now): never-run enabled hunt is due; a hunt run 1h ago with interval 24h is NOT due; run
  25h ago IS due; disabled hunt never due. (inject now as a param; deterministic.)
- POST /hunts/{id}/run with a Fake investigator returning a threat finding -> hunt_run recorded with
  the investigation run_id + mitre tag; list_hunt_runs shows it.
- enable/disable toggles reflected in due_hunts.
- scheduler tick function (call it directly with fake clock + fake client) runs exactly the due hunts.

## Model routing: sonnet-5 (scheduler + registry). No LLM in the scheduler (investigator does the thinking).
## Writing: hunt names/hypotheses are analyst-facing — plain, no em dashes.
