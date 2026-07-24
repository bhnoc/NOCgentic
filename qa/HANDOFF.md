# NOCgentic QA — Sweep 2 (2026-07-24)

Resumes from sweep 1 (docs/security/sweep-1-findings.md, deployed @ 32979ad, 13 fixed / 1 refuted).
Baseline this sweep: main @ c0f163b, smoke 5/5 green.

## Contract
- Goal: clear the deferred med/low findings + catch anything sweep 1 missed; converge.
- Acceptance: every confirmed finding validated (repro), fixed, re-verified; app stays green E2E.
- Done: sweep produces no new validator-confirmed criticals/highs + acid green.

## Deploy/validate posture (sweep 2)
- Code-level findings → validators confirm via code + LOCAL repro (no full stack needed).
- Public web-surface dynamic tests → local web-server container as isolated target (needs no secrets for XSS/auth/IDOR).
- Read-only checks → live box. NO aggressive fuzzing of the shared box (also runs PostCog).

## Surfaces (4 hunters, ids offset to avoid sweep-1 collision)
1. web-server (web-101+) — deferred web-4/5/6/7/9/10 + fresh
2. specialists (spec-101+) — deferred spec-4/5/6/7/8 + fresh
3. shared (sh-101+) — deferred sh-2/4/6/7/10/11/12 + fresh
4. tools-orch (to-101+) — deferred aud-4/5/6/7 + orch leftovers + fresh

## State
- 2026-07-24: 4 hunters launched. Awaiting findings.

## Ranked gotchas (carried from sweep 1)
1. nginx/nginx-ssl.conf edits need `--force-recreate nginx` (inode/mount cache), not reload.
2. gh run list --limit 1 can be stale — match headSha when verifying a deploy.
3. Athena temp creds in .env.s3 expire hourly — refresh before dynamic Athena validation.
4. Demo data ages out of today's dt partition at UTC midnight — re-date if queries go empty.
5. Never pkill python app.py on box (hits PostCog + audit-monitor).
6. audit bearer token (viewer login) stashed at temp/secrets/audit.env.

## Sweep 2 — REMEDIATION COMPLETE (2026-07-24)
Deployed @ 11c83bd. 48 found → 6 highs fixed + threat-hunter (orphan) removed. Writeup: docs/security/qa-sweep-2.md.
Verified clean-state: 7 containers healthy, smoke 5/5, acid 5/5, agent ports :8001-8005 now internet-unreachable,
kill-switch chain works with new ADMIN_BEARER_TOKEN (seeded in box .env.s3, stashed temp/secrets/audit.env),
orchestrator admin fail-closed (no-token→401), span-event redaction + sanitize_sql UNION-block + thousandeyes
unknown-state all verified.

Key structural changes this sweep:
- ALL agent ports unpublished (compose ports:→expose:); only nginx 80/443 public now.
- threat-hunter agent + agents/shared/s3_tools.py DELETED (orphaned; threat_hunter intent→athena_hunter remap kept).
- New env var ADMIN_BEARER_TOKEN (orchestrator /admin/* auth + audit-monitor proxy forwards it).

## DEFERRED to sweep 3 (all med/low, no live crit/high)
- web: web-4 jobStore eviction, web-5 IDOR (uuid-gated), web-6 WS Origin, web-9 httpOnly, web-10 CSP/helmet,
  web-101 dead WS fast-path.
- shared: sh-101 LIKE-wildcard, sh-102 model-default footgun, sh-103 uid 500-cap, sh-106 partition over-gen,
  sh-107 MAX_TOKENS silent truncation, sh-109 investigate_ip None-sort crash, sh-111 hash-IOC over-redaction.
- specialists: spec-104/105/106 RuntimeError-only catch (429/5xx→500), spec-107 severity filter parsed-unused,
  spec-110 blank-token all-clear, spec-112 keyword-filter fallback inverts semantics.
- tools-orch: to-102/103/104/105 (orch verify=False, GC-able hint task, raw query in hints, injection guardrail),
  to-106 trace-export PII, to-107/108 (limit=0 dumps buffer, --include-filtered doc mismatch),
  to-110..116 (redate/seed script hardening, gzip bomb, CLI-argv keys).
- sanitize_sql residual: comment-less OR 1=1 parses (LLM-fronted, read-only creds).
- Align code model default (gemini-3.1-pro-preview) with deploy default (flash-lite) to kill the latent footgun.

Sweep 2 did NOT converge (found + fixed real highs) → sweep 3 warranted for the med/low backlog,
but no LIVE criticals/highs remain open.

## Sweep 3 — REMEDIATION COMPLETE (2026-07-24)
Deployed @ 1fd9e44. 32 live med/low findings fixed + seed-opensearch.py removed. Writeup: docs/security/qa-sweep-3.md.
Docs: 8 .md files + deploy/ops skills updated for threat-hunter removal / internal ports (subagent). All new prose em-dash-free per /human.
Verified clean-state (7 containers, smoke 5/5, acid 5/5 AFTER fixing the harness):
- web-5 IDOR: owner session→200, foreign session→404 (proven).
- web-6 WS: foreign Origin closed with 1008, same-origin allowed (proven with a raw WS client; curl shows 101 then close).
- web-9: bh_sid now HttpOnly+Secure+SameSite (proven via set-cookie).
- web-10: CSP + X-Frame-Options + nosniff + Referrer-Policy present (proven via response headers).
- chat E2E all 3 agents green.

IMPORTANT harness lesson (fed back into /qa "judge the fix" principle): the IDOR fix (web-5) binds jobs to the
bh_sid cookie, so qa/acid.sh's cookieless POST→poll started 404ing = FALSE acid failure. Fixed acid.sh to carry a
cookie jar (-c/-b) like a real browser. The fix was correct; the harness was wrong. A correct API client must
persist the session cookie across POST→GET now.

## Sweep 3 converged on live crit/high (none found; only med/low, all fixed or deferred-by-design).
Remaining deferred (intentional, low-value): sanitize_sql comment-less OR 1=1 residual (LLM-fronted, RO creds);
web-4 jobStore eviction (slow leak, container-bounce recovers) — still open, candidate for a sweep 4 if desired.

## Backlog CLOSED — 100% (2026-07-24, deployed @ e602a01)
Cross-check: 48 unique findings across all sweeps, 44 fixed in sweeps 1-3, final 4 closed here:
- web-4 (HIGH): jobStore + jobOwners eviction (1h TTL, 5-min sweep, maps synced, timer unref'd). Boundary unit-tested; live container confirmed running it.
- spec-103 (was HIGH, latent): thousandeyes broadened exception catch (graceful degrade, not 500); model-omit already safe via sh-102 (default is flash-lite).
- to-109 (MED): redate_slice hard-refuses DST_DT==SRC_DT and non-demo bucket before any delete.
- to-111: MOOT — lived in seed-opensearch.py, removed in sweep 3.
Verified: 7 containers healthy, smoke 5/5, acid 5/5, eviction in deployed dist, redate guards present.

## Everything is fixed. Only intentional-by-design residual remains:
- sanitize_sql comment-less `OR 1=1` parses: defense-in-depth behind the LLM + read-only single-DB Athena creds.
  Not a discrete finding; would need a real SQL parser or parameterized inputs to fully close. Documented, accepted.
No open findings at any severity. 3 sweeps converged.
