# SLICE 7 — Self-improving memory: drift stats + auto promote/retire (level9000)

## Contract
- **Goal:** Close the learning loop. Measure whether each active/candidate memory helps or hurts
  investigation outcomes, and auto-promote (helped) or auto-retire (hurt) it — statistically, with an
  off/shadow/live trust ladder and a full audit. Completes "Automated Learning" / self-tuning memory.
- **Acceptance (observable, via API + unit):**
  1. PURE stats (ported from VR driftStats.ts): `two_proportion_z_test`, `wilson_interval`,
     `cusum_upper`, `assess_drift` — unit-tested against known inputs (a clear degradation → z>1.96 +
     valid; tiny sample → invalid/insufficient; a clean improvement → negative delta). NO PG, NO LLM.
  2. Outcome recording: when an investigation used memories (the investigator already bumps usage),
     also record the run's OUTCOME per memory so drift has data. Add `memory_outcomes` (memory_id,
     run_id, failed bool, at). A memory "failed" for a run = the run's finding verdict was a false
     positive OR the run errored (code rule). `record_memory_outcome(memory_id, run_id, failed)`.
  3. `assess_memory_drift(memory_id, split_at)` → pulls the memory's outcomes before/after the split
     (split = memory's promoted_at or created_at), runs assess_drift, returns {level, z, delta_pct,
     drift_score_pct, reason}. level ∈ ok|insufficient_data|watch|alert|improving.
  4. `plan_action(drift)` (PURE, ported): retire if ACTIVE/CANDIDATE hit 'alert'; promote if CANDIDATE
     hit 'improving'; adjust_confidence otherwise; None if no action. Unit-tested per branch.
  5. Sweep with a MODE ladder: `POST /memory/sweep {mode}` mode ∈ off|shadow|live.
     - off: measure only, update drift_score_pct, emit nothing actionable.
     - shadow: record what it WOULD do as a `memory_proposal` row + return the proposals (no state change).
     - live: apply (transition_memory promote/retire, or confidence nudge), write memory_events, return actions.
     Default mode = off (safe). Illegal/unknown mode → 400.
  6. Convergence safety: retired memories are excluded from future sweeps (no thrash); the sweep is
     idempotent given the same outcomes.
- **Done:** acid green from clean (test_drift_stats.py pure + test_memory_selfimprove.py PG-backed:
  outcome recording, drift assessment, plan_action branches, off/shadow/live sweep). Container smoke.

## Architecture — extend memory service + store; new pure stats module
- `agents/shared/drift_stats.py` (NEW, PURE): port VR driftStats.ts EXACTLY.
  - Z_95=1.96, Z_99=2.576.
  - `two_proportion_z_test(fails_before,n_before,fails_after,n_after) -> dict` {rate_before,rate_after,
    delta_pct,n_before,n_after,z,valid,invalid_reason}. Pooled p̂; validity gate: total n>20 AND each
    expected fail/ok count >10 else invalid. (formulas in VR file lines 52-101 — match them.)
  - `wilson_interval(fails,n,z=Z_95) -> (low,high)` (VR lines 109-119).
  - `cusum_upper(outcomes: list[bool], baseline_rate, k=?, h=?) -> {peak,triggered,alarm_at}` (VR 141+).
  - `assess_drift(fails_before,n_before,ordered_after_outcomes:list[bool]) -> {level,z,delta_pct,
    drift_score_pct,reason,ci}`: level='improving' if delta<0 & significant-ish; 'alert' if z>Z_95 or
    cusum triggered; 'watch' if trending; 'insufficient_data' if test invalid; else 'ok'. (VR assessDrift 189+.)
  - `plan_action(status, level) -> {"action": "retire"|"promote"|"adjust_confidence"|None, "reason"}` (VR planAction).
- New migration `0004_memory_drift.sql`: `memory_outcomes` (id, memory_id FK, run_id, failed bool, at)
  + `memory_proposals` (id, memory_id FK, action, reason, drift_score_pct, status default 'open', created_at).
  Indexes on memory_id.
- store.py: record_memory_outcome, memory_outcomes_split(memory_id, split_at)->(fails_before,n_before,
  ordered_after:list[bool]), assess_memory_drift(memory_id), update_drift_score(memory_id,pct),
  create_memory_proposal(...), list_memory_proposals(status), run_memory_sweep(mode) OR keep the sweep
  logic in the service. (Prefer: pure stat fns in drift_stats.py; DB glue in store; orchestration in service.)
- memory service: POST /memory/sweep {mode}, GET /memory/proposals, POST /memory/{id}/outcome
  {run_id, failed}. Reuse existing transition_memory for live actions.
- INTEGRATION (light): investigator already bumps usage + emits memory_write. Add: after a run finishes,
  the investigator (or a small hook) records a memory_outcome per injected memory with failed = (verdict
  false-positive/benign-but-expected-threat? keep simple: failed = run errored OR finding.verdict was a
  known-FP). KEEP THIS MINIMAL and behind the existing guard; if it's awkward to wire cleanly, expose
  POST /memory/{id}/outcome and have triage/hunter call it — but do NOT block the slice on deep wiring.
  The testable core is the stats + sweep; the outcome feed can be API-driven for now.

## Tests
- tests/python/test_drift_stats.py (PURE): z-test known values, validity gate, wilson bounds [0,1],
  cusum triggers on sustained failures, assess_drift levels, plan_action all branches. MUST run w/o PG.
- tests/python/test_memory_selfimprove.py (PG): record outcomes; assess_memory_drift with a seeded
  degradation → 'alert'; off/shadow/live sweep (shadow writes proposals no state change; live retires an
  alerting active memory + writes memory_events; off changes nothing but drift_score). retired excluded.

## Model routing: sonnet-5. The stats are exact ports — if the z-test/cusum unit values are wrong,
## that's a correctness bug; escalate a review to opus rather than accept fuzzy numbers.
