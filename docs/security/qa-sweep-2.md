# NOCgentic QA Sweep 2: Findings and Remediation

**Date:** 2026-07-24
**Scope:** Full codebase, resuming from sweep 1. Cleared the sweep-1 deferred med/low backlog and re-hunted for anything missed.
**Method:** 4 hunter agents (web-server, specialists, shared, tools+orchestrator) → 48 findings. Adversarial validators confirmed/refuted each critical/high, reproducing exploits locally and against an isolated local web-server container + read-only checks on the live box. Only validator-confirmed issues fixed. Deployed via the runner, verified from a clean state (smoke + acid green + targeted per-fix checks).

**Result:** 48 found (0 crit, 12 high, 22 med, 14 low) → **6 highs fixed + 1 orphaned agent removed**. Validators corrected 3 over-claims and refuted/dead-coded the rest. Deployed at commit `11c83bd`.

The headline: the adversarial validation step paid for itself again — it downgraded half the "highs" (web-4, web-7, to-109) and, crucially, found that **the sweep-1 kill-switch hardening was bypassable** (to-101) and that **an entire agent was dead code** (threat-hunter).

---

## Confirmed & fixed

### to-101 — Orchestrator admin was internet-reachable and unauthenticated (HIGH, live exploit)
Sweep 1 hardened the audit-monitor *proxy* in front of the kill-switch (required a bearer there). But the orchestrator's own `/admin/killswitch` (GET) and `/admin/killswitch/athena` (POST) had no auth, and `docker-compose.agents.yml` published orchestrator on `"8001:8001"` to the host's public interface. A validator hit `http://aing.bhnoc.com:8001/admin/killswitch` **from the internet and got `200 {"athena_hunter":false}`** — the sweep-1 gate was fully bypassable, gated only by the AWS security group. Every agent (8001-8005) was published the same way.

**Fix (defense-in-depth, both layers):**
- **Network:** all agent ports (8001-8005) changed from `ports:` to `expose:` in compose — internal docker network only, matching web-server/audit-monitor. The app never needed them published (agents talk via compose service names like `http://orchestrator:8001`). nginx → web-server → orchestrator → agents all stay internal.
- **App:** orchestrator `/admin/*` now requires `ADMIN_BEARER_TOKEN` (fail-closed: unset = deny all). The audit-monitor proxy forwards that token so the kill-switch UI still works.

**Verified:** all of :8001-8005 now refuse connections from the internet (were 200); nginx `/admin` → 404; internal orchestrator admin with no token → 401; kill-switch via the audit-monitor proxy (with token) → 200. Exploit closed at both layers.

### sh-105 — sanitize_sql let UNION / tautology / stacked statements through (HIGH)
`sanitize_sql` was a DDL/DML keyword blocklist only. A validator imported the real function and passed `UNION SELECT`, `OR 1=1`, comment-injection, and stacked-statement payloads unmodified. It's reachable: `execute_custom_sql` runs LLM-generated SQL and the analyst query is interpolated into the SQL-gen prompt. **Fix:** reject `UNION`, SQL comments (`--`/`/* */`/`#`), and stacked statements (semicolon), on top of the existing blocklist; case-insensitive, whole-statement. Preserves the `-> str` / raises-`ValueError` contract. **Residual (accepted):** a comment-less `OR 1=1` still parses. It's defense-in-depth behind the LLM, and the Athena creds are read-only on a single DB, so worst case is cross-table disclosure within `blackhat_pope_logs`, not writes or cross-tenant. Flagged for a future parameterized-input pass.

### sh-110 — Redaction missed span events (HIGH, partial regression of sweep-1 sh-8)
Sweep 1's redacting SpanProcessor scrubbed span *attributes* but not span *events*. In this stack LLM prompts are recorded as OTEL events, and `s3_span_exporter` serializes event attributes verbatim to S3 + Manifold, so raw prompts/PII bypassed redaction. **Fix:** the SpanProcessor `on_end` now also walks `span._events` and redacts each event's attributes through the same `_redact`/`_is_sensitive_attr` helpers, in a separate defensive try/except. Verified with a stub span: event attrs (internal IP, password, api_key) now scrubbed.

### spec-109 — thousandeyes reported unmeasurable tests as GREEN (HIGH, false all-clear)
When `fetch_latest_results` returned `{}` (404/timeout/exhausted), `_classify(None,None,...)` returned `"green"`, so a monitoring test that couldn't be measured inflated the healthy count — the agent told operators "all systems green" while blind. **Fix:** unmeasurable tests get a distinct `unknown` state (not green, not red); the summary carries `unknown_count`/`unmeasured_tests`; the LLM prompt is told these are blind spots. Purely additive schema. Verified: empty fetch → `unknown`, healthy → `green`.

### threat-hunter removed (orphaned dead code — user decision)
Validators confirmed threat-hunter is never routed to: `call_threat_hunter` was defined but never invoked, and the `threat_hunter` intent maps to `athena_hunter`. Its container shipped and ran for nothing. Removed `agents/threat-hunter/` and its sole-consumer dead lib `agents/shared/s3_tools.py` (proven zero other importers), plus the dead threat-hunter fallback-hints branch. This disposed of findings sh-104, sh-108 (both in s3_tools) and spec-102, spec-108 (dead code). The `threat_hunter → athena_hunter` remap stays — that's the live path that answers threat-hunty queries.

---

## Validator-corrected (why we didn't fix as filed)
- **web-4** (jobStore leak) → MEDIUM not high: per-IP rate limit + small entries make it a slow eventual-OOM over conference duration, recoverable by a container bounce. Deferred.
- **web-7** (3-octet 10/8 redaction leak) → LOW: the code (`agent-sdk/src/llm/client.ts`) is DEAD — nothing imports `@bhnoc/agent-sdk`. The live LLM path is the Python client. Deferred/irrelevant.
- **to-109** (redate_slice destructive delete) → MEDIUM not high: operator script (not request path) that only ever targets the re-datable demo destination partition, never source data. Deferred.
- **spec-102 / spec-103** (model drift to pro-preview + thinking_budget 400 trap) → REFUTED for prod: compose pins `GEMINI_MODEL=gemini-3.5-flash-lite` on every service, so the flash-lite clamp fires and no pro model is hit (proven dynamically: live call reported `model=gemini-3.5-flash-lite`). Latent footgun only (code default disagrees with deploy default).

---

## Deferred to a future sweep
web-4 (jobStore eviction/TTL), web-5 (IDOR on chat/:id + WS subscribe — uuid-gated, med), web-6 (WS Origin check, low), web-9 (httpOnly cookie), web-10 (CSP/helmet), web-101 (dead WS fast-path — polling is the real render path), and the assorted med/low across shared (sh-101/102/103/106/107/109/111) and specialists (spec-104/105/106/107/110/112). The sanitize_sql `OR 1=1` residual. Latent model-default footgun (align the code default with the deploy default). None are live criticals/highs.

## Verified (clean-state)
- Local Docker build of web-server = TS typecheck (retroactively covers the sweep-1 TS edits + OpenSearch removal, which had no local typecheck at the time). All green.
- Post-deploy: 7 containers healthy (threat-hunter gone), smoke 5/5, acid 5/5 (threat query correctly routes to athena-hunter).
- Per-fix: agent ports :8001-8005 refuse internet connections; nginx `/admin`→404; internal orchestrator admin no-token→401; kill-switch via proxy with token→200; span-event redaction confirmed via stub; sanitize_sql rejects the 4 payloads, accepts legit queries; thousandeyes empty-result→unknown.

## Gotchas (carried + confirmed)
- nginx config change → `--force-recreate nginx` (this sweep didn't touch nginx, so no recreate needed).
- New env var (`ADMIN_BEARER_TOKEN`) is box-authoritative in `.env.s3`, not in git — seeded before deploy or the kill-switch chain fails closed.
