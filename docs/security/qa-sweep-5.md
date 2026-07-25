# NOCgentic QA Sweep 5: Findings and Remediation

**Date:** 2026-07-25
**Scope:** Two things the playbook calls for after a non-converging sweep: judge sweep-4's fixes for regressions, and run the aggressive security pass (deferred across all prior sweeps) on an isolated local container. Plus a fresh-eyes read of the highest-churn files.

**Result:** 9 findings (0 critical, 0 high, 4 medium, 5 low). The aggressive security pass came back clean on every real exploit class. The findings were incomplete prior fixes and polish, not new vulnerabilities. Deployed at `3bda0f4`, verified from a clean state.

## The aggressive security pass (the deferred one) came back clean

Ran 7 attack classes against an isolated local web-server container (`:3002`, never the shared box): input validation and injection on `/api/v1/chat`, rate-limit bypass, IDOR, security headers and cookie flags, WebSocket, error-leak paths, and static path traversal. The process never crashed. What held up:

- **Input validation:** oversized body to 413; bad types/empty/oversized query to 400 "Invalid query" (no schema leak); `__proto__`/`constructor` to 400 "forbidden prototype property"; null-byte/control/unicode/duplicate-key/deeply-nested all handled.
- **IDOR:** owner polls fine; a different jar, no cookie, forged bh_sid, and guessed UUIDs all get 404 (no existence oracle).
- **Headers:** CSP, X-Frame-Options DENY, nosniff, Referrer-Policy on 200/404/static/error; bh_sid is HttpOnly+Secure+SameSite on every Set-Cookie.
- **WebSocket:** foreign and null Origin closed with 1008; malformed and 2 MB frames ignored, no crash.
- **Static traversal:** `../`, encoded, null-byte all 403/404, no source disclosure.
- **Errors:** no stack traces, file paths, dep versions, or Zod schema leaked in any body.

Only two rate-limit findings came out of it (below). That is a strong signal the public surface is solid.

## Fixed: the two half-done sweep-4 fixes

Sweep 5's main value was catching two sweep-4 fixes that were applied to only one of two sites, exactly the "changing a shared value, sweep every occurrence" trap.

**fc-1 / reg-3 (medium): severity labeling diverged across agents.** Sweep 4's ql-8 aligned the numeric Suricata mapping (1/2/3) between athena-hunter's `_normalize_severity` and alert-triage's `_norm_sev`, and left a comment claiming they were "kept identical." They were not: on word inputs they still diverged (`'error'` gave low vs high, blank/garbage gave low vs unknown), so the live `/alerts/recent` feed and the triage view labeled the same alert differently. Fix: `_normalize_severity` now mirrors `_norm_sev` exactly, including the `_WORD_SEV` folds and the "unknown" fallthrough (unrecognized/blank/4+ now returns "unknown", not a buried "low"). Verified with a 10-input parity table: all 10 match. The shared `Alert` TS type gained `'unknown'` so the feed can carry it.

**reg-1 (medium): capped counts presented as totals in alert-triage.** Sweep 4's ql-9 added a "SAMPLED / at least N" flag to athena-hunter's counts, but the fields the sweep-4 doc named (total_alerts/flows/dns) actually live in alert-triage, still bare `len()` of LIMIT-capped result sets fed to the LLM and UI as true totals. Fix: mirrored athena-hunter's cap-detection (`len == LIMIT`), so a capped count is now labeled "at least N (SAMPLED)" to the LLM with `*_capped` flags for the UI, and an under-cap count passes through as a true total unchanged.

## Fixed: rate limit

**sec-1 (medium): rate-limit rejections returned 500, not 429.** The `errorResponseBuilder` returned an object with no `statusCode`, so Fastify defaulted to 500. This breaks client backoff and trips the ops ">1% API error rate" alarm. Fix: return `statusCode: 429`. Verified on a rebuilt container: 120x202 then 429s, zero 500s.

**sec-2 (medium): rate limit bypassable by rotating X-Real-IP, but topology-mitigated.** The keyGenerator trusts the client-appendable X-Real-IP header. The fix now ignores malformed/list values (falls back to req.ip), which closes the trivial junk-rotation case. Rotating VALID IPs still mints separate buckets, which is inherent to header-based keying. This is not exploitable in the real deploy: web-server is `expose:`-only (unreachable except through nginx) and nginx overwrites X-Real-IP with `$remote_addr`. Decision (yours): accept as topology-mitigated and document the dependency. Recorded in the ops skill: if web-server or any agent is ever published to the host with `ports:`, the rate limit becomes bypassable, so keep them internal-only.

## Fixed: polish (low)

- **fc-3:** `_ZONE_RE` (the output zone-name scrubber) matched the singular English word "tool" (via `Tools?`) and was case-sensitive (lowercase "tools"/"registration" evaded the scrub). Now case-insensitive and matches "Tools"/"Registration" exactly, not "tool". Closes both a scrub-evasion and a false-trigger.
- **fc-2:** removed dead `agent_used` sentinels from the background-hints guard ('orchestrator' is always reassigned before that line, 'guardrail' is never assigned). Only 'error' was live.
- **fc-4:** reconciled contradictory comments about Gemini `thinking_budget=-1` (it is DYNAMIC/model-decided, not "minimal"; bounded output needs an explicit positive budget, as athena-hunter's SQL gen uses).

## The fix that didn't work the first time
sec-2's first fix only rejected malformed X-Real-IP. Testing against the isolated container proved a rotated VALID IP (`10.0.0.1`, `10.0.0.2`, ...) still bypassed the cap, because each is a well-formed single IP that mints its own bucket. That is the actual attack. The honest conclusion: you cannot distinguish "behind nginx" from "direct hit" by the header alone, and the real control is the topology (expose-only + nginx overwrite), so it is documented rather than papered over with a fix that does not hold. This is the "judge the fix as hard as the finding" principle catching a fix that looked right but wasn't.

## Verified (clean-state)
Deploy `3bda0f4` rebuilt the stack; smoke 5/5; acid 5/5. Per-fix: severity parity table 10/10; rate-limit 429 (not 500) proven on a rebuilt container; TS build and Python parse clean; all new code em-dash-free. Note: athena-hunter briefly showed low confidence post-deploy because the demo slice had aged out of "today" (the documented daily-rollover, now re-dated to 2026-07-25); after re-dating it returned to 0.95, confirming the confidence-sentinel change reports low only on genuinely empty data.

## Convergence
This sweep found no criticals or highs, the aggressive pass was clean, and the mediums were all incomplete-prior-fixes now closed. The sweep is effectively converged: what remains is documented and accepted (the sanitize_sql `OR 1=1` residual from sweep 2, the topology-dependent rate-limit keying, and LLM prose noncompliance on the unknown-count clause). No open findings at any severity that are exploitable or correctness-critical in the real deploy.
