# QA Sweep — level9000 additions, Sweep 2 (2026-07-30)

Resumes from sweep 1 (docs/security/qa-sweep-level9000-1.md). Two tracks: (a) **re-hunt the
sweep-1 fixes** (new code is where fixes hide deeper bugs, principle 6), and (b) clear the
deferred low/medium findings. Baseline: 398 python + 36 vitest green.

## Result
- Re-hunt of sweep-1 fixes found **8** (2 high, 3 medium, 3 low) + fixed **13 deferred** from sweep 1.
- The two HIGHs were sweep-1 fixes that over- or mis-corrected — exactly the "a fix is a new bug"
  pattern the methodology warns about:
  - **s2-01 (HIGH):** the sweep-1 sanitizer broadening FALSE-REDACTED benign operational memory
    ("from now on tag scanner alerts…", "do not report duplicate beacons", "user: joe reported…").
    A sanitizer that eats the memory it protects is its own bug.
  - **s2-02 (HIGH):** triage's severity model (higher-int = worse) was INVERTED vs the repo's
    canonical Suricata/Corelight convention (1 = highest), confirmed by DATA-SCHEMA.md, athena-hunter,
    root-cause, and seed_demo.py. A sev-1 beacon sorted BELOW a sev-3 scan and a recurring critical
    wouldn't reopen a dismissed low. The sweep-1 tri-3 fix inherited and amplified this.
- **0 refuted from the re-hunt as false alarms**, but the re-hunt REFUTED (confirmed correct) a batch
  of sweep-1 fixes: inv-1 stripper, inv-3 full-row detection, drift reorder, densify, ui-1 binding,
  px-1/2, st-4 locks, NFKC (no benign corruption), the broadened patterns' ReDoS (linear). Good fixes stayed.

## Fixed (with gate)
| id | sev | fix |
|----|-----|-----|
| s2-01 | high | sanitizer tightened: dropped the over-broad bare patterns (from-now-on / instead / output-the-following / the-actual-instructions), narrowed always-/do-not-, dropped `user:` role token. Two-sided corpus gate: 21 benign phrases pass untouched AND all injection strings still redacted. |
| s2-02 | high | severity canonicalized to **1 = highest** across triage: list ORDER BY severity ASC, LEAST() on dedup (keep worst), tri-3 reopens on new < old; added `normalize_severity(raw, source)` ingest seam for the heterogeneous Corelight sources (Suricata, Zeek notice, anomaly, ML) with a documented invariant; UI sevLabel commented. sweep-1 tri-3 tests rewritten to the corrected convention. Verified live: sev-1 beacon sorts first. |
| s2-03 | med | emit() retries on UniqueViolation (recompute MAX(seq)+1, ≤5 attempts) so the st-2 unique index errors are handled, not 500s |
| s2-04 | med | reap_stale_validating clamps older_than_minutes ≥1; POST /triage/reap Query(ge=1) → 422 on 0/negative (no more reaping in-flight investigations) |
| s2-05 | med | embeddings classify auth errors by exception TYPE (not broad substrings); InvalidArgument treated transient unless api-key phrase; root-cause wraps embed() → clean 503, not uncaught 500 |
| mem-5 | med | candidate memories can now auto-promote: split at the candidate-transition event timestamp (from memory_events) so there's a real before/after window |
| mem-6 | med | confidence adjustment converges to a target (watch→40, improving→80) instead of ±10 every sweep → repeated sweeps are idempotent |
| rc-6 | med | /investigate query now scopes spike selection (IP/signature substring match) instead of ignoring it |
| rc-10 | low | fetch_events uses shared sanitize_value + degrades to a prefix LIKE when a signature contains comment-like text (no more silently losing all events) |
| rc-11 | low | a strong similar-incident match (distance < 0.15) now beats a merely-present deploy marker for root_cause |
| inv-8 | low | dt partition hint computed from the real window (date_partitions) so a 48h window near midnight lists all 3 partitions |
| s2-07 | low | dt-filter guard now requires the dt predicate after WHERE (rejects `SELECT dt=1 …` projection false-accept) |
| st-6 | low | template premask masks domains before integers → hostnames with digit runs aren't fragmented into different templates |
| st-7 | low | domain regex skips tokens > 253 chars (FQDN max) → no quadratic backtracking on long dotless tokens |
| ui-2 | low | Glass Box sorts events by seq before rendering (defensive) |
| ui-3 | low | unknown bucket label escaped once, not twice |
| hnt-4 | low | scheduler runs one tick immediately, then sleeps → fresh-deploy hunts don't wait a full interval |
| hnt-5 | low | POST /hunts/{id}/run on a disabled hunt → 409 unless ?force=true |
| s2-06 | low | documented: in-flight set is process-local (multi-replica needs a DB advisory lock); httpx keeps its 120s timeout |

## Verification
- Full python suite from a DROP/CREATE-SCHEMA'd DB: **445 passed** (was 398 → +47 gates). web-server: **36 vitest**, tsc clean.
- Cold `docker compose up --build` of all 5 services on a fresh pgdata volume: all init schema cleanly; live triage confirms a sev-1 beacon sorts first (severity convention fix works end-to-end).
- Both HIGH gates proven to FAIL pre-fix: reverting severity ASC→DESC reddens the queue-order/reopen
  tests; re-adding an over-broad sanitizer pattern reddens the benign-corpus test.

## Deferred / accepted (unchanged from sweep 1)
- App-wide auth model (tri-4/px-3/px-4) — user decision: keep no-auth internal-only, deliberate app-wide
  decision for later. mem-9 (rationale never injected today). All documented in sweep-1 report.

## Convergence
This sweep found only sweep-1-fix regressions + the deferred lows; no NEW criticals in unchanged code.
The two highs were fix-induced and are now closed with two-sided gates. **A sweep 3 is not warranted**
unless new features land — the confirmed-finding set has converged (re-hunt surfaced only fix-quality
issues, now resolved). Recommend a light re-hunt only after the orchestrator-wiring work (the one large
deferred item) is done on the box.

---

## Sweep 2 — cleanup pass (all deferred lows/mediums, 2026-07-30)

Cleared the remaining 14 non-auth findings (4 medium: inv-4, rc-4, st-3, tri-5; 10 low). Auth findings
(tri-4/px-3/px-4/mem-9) stay deferred per the user's keep-no-auth decision.

| id | sev | fix |
|----|-----|-----|
| inv-4 | med | severity computed over the FULL de-duplicated high-signal set (detect_high_signal_full), not the [:6] display cap → a 7th+ beacon family no longer downgrades critical→high |
| rc-4 | med | detect() preserves the peak spiking bucket; marker correlation uses a tight window around the peak (peak-5m .. peak+1h), not the whole investigation window |
| st-3 | med | upsert_memory retries on UniqueViolation (version-bump race), mirroring emit() |
| tri-5 | med | build_alert_query passes alert fields as delimited <alert> DATA + strips control chars → closes the prompt-injection channel into the investigator |
| inv-5 | low | validate_query fast-rejects WITH/CTE (athena engine is SELECT-only) instead of burning a tool round |
| inv-7 | low | unknown tool name emits a rejection tool_result (no dangling function call to the provider) |
| mem-8 | low | POST /memory maps UniqueViolation/IntegrityError → 409, not 500 (defense in depth over st-3) |
| st-8 | low | FixtureProvider.seen_messages uses deepcopy (no retroactive snapshot mutation) |
| st-9 | low | tool_provider tolerates args=None / missing tool-call keys (no TypeError/KeyError) |
| st-10 | low | init_schema: clear error when no migrations found; RECALL_MIGRATION_PATH=file runs exactly that file |
| st-11 | low | PG_DSN unset logs a clear WARNING (still uses dev default) |
| s2-08 | low | CREATE EXTENSION DDL gated behind a once-per-process flag (advisory lock only on first connection) |
| tri-6 | low | POST /alerts typed with a Pydantic model (422 not 500), batch capped at 1000, empty-field dedup key is a safe hash |
| tri-7 | low | dedup_key is sha1(json([sig,src,dst])) — no '|' separator collision |
| ui-2/ui-3 | low | (already in the main sweep-2 fix set) |

**A weak gate caught and hardened:** the inv-4 test initially passed regardless of the fix because one
of its 6 "non-beacon" families was named "...Ransomware Beacon" (tripped the beacon regex anyway).
Renamed it so families 1-6 contain no beacon/c2 keyword; the gate now fails against the capped path and
passes against the fix (proven by revert).

**A flaky test fixed at the source:** `TestExtensionEnsuredFlag` asserted the module-global
`_extension_ensured` flag was already True, relying on some earlier test having opened the pool — order-
fragile in the full cross-file run. Rewrote it to open a pooled connection itself (establish the
precondition), removing the order dependence. Full suite now deterministic green across repeated runs.

### Verification
- python **481 passed** (was 445 → +36 gates), 3 consecutive fresh-DB runs + reversed-file-order run all green.
- web-server **36 vitest**. inv-4 gate proven to bite after hardening.

### Status: all confirmed non-auth findings across both sweeps are now fixed. Only the auth-model
### decision (deferred by the user) and orchestrator-wiring (box-side) remain open.
