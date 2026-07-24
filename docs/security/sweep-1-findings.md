# NOCgentic Security and Correctness Sweep 1: Findings and Remediation

**Date:** 2026-07-24
**Scope:** Full codebase (agents, shared libs, web-server, audit-monitor, nginx) ahead of the Black Hat Asia conference deployment.
**Method:** Hunter agents fanned out over 6 non-overlapping surfaces → 61 raw findings. Adversarial validator agents independently confirmed or refuted each critical/high finding from the actual code (reproducing exploits locally, and querying live Athena where relevant). Only validator-confirmed issues were fixed. Fixes deployed via the self-hosted runner and verified end-to-end from a clean state (smoke + acid green, plus targeted per-fix checks).

**Result:** 61 found → 14 critical/high triaged → **13 fixed, 1 refuted**. Deployed at commit `32979ad`.

Why this doc exists: so the next person knows what was wrong, what we changed, and how we proved it, without re-running the whole sweep.

---

## Confirmed & fixed

### CRITICAL

**aud-1: Trace viewer auth was fail-OPEN (`tools/audit-monitor/app.py`)**
The `/bh/1337/thetraces/` trace viewer exposes raw LLM prompts, generated Athena SQL, user queries, and internal NOC IPs. Its session cookie is HMAC-signed with `AUDIT_COOKIE_SECRET`, or, if unset, `sha256(AUDIT_BEARER_TOKEN)`. On the box **both were blank**, so the signing key was the empty string. A validator reproduced the exploit locally: anyone who knows the URL can forge a valid `bh_audit` cookie with an empty-key HMAC and read everything. Fail-open, not fail-closed. At a hacker conference where 443 opens to attendees, that URL gets found.

**Fix (defense-in-depth, two layers):**
- **Layer A: nginx edge allow-list.** `/bh/1337/thetraces/` in `nginx/nginx-ssl.conf` is now restricted to operator IPs (`allow` the SG dev allow-list, `deny all`). The box terminates TLS, so `$remote_addr` is the true client IP. The viewer is never publicly reachable even when 443 opens to the audience.
- **Layer B: app auth is now safe-by-default.** The cookie secret is never empty and never derived from the bearer token: use `AUDIT_COOKIE_SECRET` if set, else a strong random per-process secret (`secrets.token_urlsafe(32)`). Forgery is impossible even fully unconfigured.

**Verified:** forged empty-key cookie → **401** (was 200 + full data). Bearer token → 200 with data. Allow-listed operator IP reaches the login; everyone else is denied at nginx.

### HIGH: security

**aud-2: Misleading fail-open startup log (`audit-monitor/app.py`)**
Startup logged "AUDIT_BEARER_TOKEN is not set, every request will 401" and kept serving. It did *not* 401 (see aud-1), so operators were told it was locked when it was wide open. That lie is what let the blank-token deploy ship. **Fix:** blank bearer now genuinely denies all (stays up, no crash-loop) with an accurate warning: "trace viewer is LOCKED (deny-all)."

**aud-3: Kill-switch rode the same broken auth (`audit-monitor/app.py`)**
The Athena kill-switch admin endpoints (`/admin/killswitch/athena`) were gated only by the viewer's session cookie, so a forged cookie let an outsider silently disable the SOC's Athena agent (operational DoS). **Fix:** state-changing admin POSTs now require a valid Bearer *header*, not just a cookie. The viewer UI does a step-up token prompt on the kill button. (Read-state GET stays cookie-only, non-destructive.)

**orch-1: Restricted internal IPs leaked to the external LLM (`agents/orchestrator/main.py`)**
Background hint generation forwarded the raw downstream answer to Gemini *before* the output sanitizer ran, so internal IPs/zone-names the sanitizer masks were shipped to the external model unmasked. A validator saw real IP `10.220.69.140` leak on a live query. **Fix:** sanitize the answer/data before spawning the hint task, and again inside `generate_hints` as defense-in-depth. Contradicted the CLAUDE.md "No PII to external LLMs" rule; now enforced.

**web-1: Rate-limit bypass via spoofed `X-Forwarded-For` (`packages/web-server/src/index.ts`)**
`trustProxy: true` made `request.ip` come from the client-appendable left-most `X-Forwarded-For`; `@fastify/rate-limit` keyed on it, so a fresh XFF per request minted a new bucket → unlimited requests on the only LLM-cost endpoint (`/api/v1/chat`). Validator confirmed dynamically (fresh XFF reset the counter). **Fix:** rate-limit now keys on nginx's `X-Real-IP`, which nginx overwrites and the client can't spoof past the edge.

**sh-1: SQL injection via truncate-after-escape (`agents/shared/athena_client.py`)**
`sanitize_value` doubled single-quotes to escape them, *then* truncated to 500 chars, so a ~499-char value whose escaped `''` straddled the boundary got chopped back to a lone trailing quote, breaking out of the SQL string literal. Reproduced with the real function; reachable from 20+ IOC-driven call sites. **Fix:** truncate the raw input *before* escaping, so no doubled pair can be split.

**spec-2: Second-order prompt injection (`agents/alert-triage/main.py`, `agents/threat-hunter/main.py`)**
Athena result rows (DNS names, User-Agents, TLS SNI, all attacker-controllable by generating traffic at the conference) were embedded verbatim into the LLM prompt; only the analyst query was sanitized. An attendee could steer the triage/hunt model via crafted traffic. **Fix:** fence the telemetry rows in an explicit `<<<UNTRUSTED_TELEMETRY ... >>>` block and instruct the model (system prompt) to treat everything inside as data only, never instructions.

### HIGH: correctness

**orch-2: Internal details leaked in 500s (`agents/orchestrator/main.py`)**
Only `httpx.ConnectError` was handled gracefully; downstream timeouts and HTTP errors fell through to `HTTPException(500, detail=str(exc))`, leaking the internal agent URL and exception internals to the caller. **Fix:** catch `ConnectError`/`TimeoutException`/`HTTPStatusError` gracefully (degraded answer, `agent_used='error'`); the outer fallback returns a static "Internal error processing request" with the real exception only in server logs.

**ath-1: Multi-day queries silently returned nothing (`agents/athena-hunter/main.py`)**
The prompt told the model to emit `dt >= 'START_DATE'` for "last N days / past week", but `START_DATE`/`START` was never substituted with a real date, so those queries matched zero partitions. **Fix:** added `start_date`/`start` → 7-days-ago to the token-substitution map.

**ath-2: Invalid SQL when no WHERE clause (`agents/athena-hunter/main.py`)**
When a generated query had no WHERE, the date-partition injector appended `WHERE dt=...` to the *end* of the string, producing invalid SQL if there was a `GROUP BY`/`ORDER BY`/`HAVING` (`... GROUP BY x WHERE dt=...`). **Fix:** insert the partition predicate *before* the first `GROUP BY`/`ORDER BY`/`HAVING`/`LIMIT` keyword, appending at the end only if none are present.

**spec-1: IDS criticals mis-bucketed as low priority (`agents/alert-triage/main.py`)**
Suricata alerts store `alert_severity` as a varchar number (`"1"/"2"/"3"`, confirmed via live Athena), but the scorer/breakdown keyed on word strings (critical/high/medium/low). Every IDS alert scored at baseline and bucketed "low," so genuine critical detections sorted out of `prioritized_alerts[:15]` and could never reach the LLM. **Fix:** a `_norm_sev()` normalizer (1→high, 2→medium, 3→low; also folds "informational (default)"/"notification"/"error") applied at both lookup sites.

### MEDIUM

**sh-8: Unredacted prompts/SQL/IPs exported to external OTLP + S3 (`agents/shared/telemetry.py`)**
LangSmith/OTEL auto-capture exported raw prompts, completions, and logged SQL (with internal IPs) to the external Manifold OTLP endpoint, a permanent S3 archive, and console. The per-agent `sanitize()` only scrubbed the LLM *input string*, not span attributes or log records. Gated on `OTEL_EXPORTER_OTLP_API_KEY` (unset by default), so it only bites in the prod deploy where the key is set, hence medium. **Fix:** a redacting SpanProcessor scrubs sensitive span attributes before export, and a redacting logging.Filter scrubs log records; `athena_client` no longer logs raw SQL bodies.

**ath-3: IOC injection hardening (`agents/athena-hunter/main.py`)**
`classify_iocs` used `_RE_DOMAIN.search()` (not `fullmatch`), so a quote-bearing string was accepted as a "domain" and interpolated into the SQL-gen prompt unescaped. Downgraded from high: it's LLM-mediated prompt injection, not direct SQLi, and the normal orchestrator path strips IOCs before they arrive, a defense-in-depth gap, not a reliable direct exploit. **Fix:** `fullmatch` instead of `search`, and run every IOC through `sanitize_value()` before prompt interpolation.

### Cleanup

**sh-9: Dead OpenSearch code removed**
The project migrated OpenSearch → Athena. `agents/shared/opensearch_tools.py` and `packages/shared/src/opensearch*` had zero live importers and shipped `verify=False` (TLS disabled). Proven dead by full-repo grep, then removed (barrel `index.ts` export line dropped, `./types` kept). `scripts/seed-opensearch.py` was **kept**: it's a standalone operator/demo tool referenced only by docs, not imported.

---

## Refuted (found by a hunter, killed by a validator)

**web-2: "DOM XSS in `renderThousandEyesData`"**. REFUTED. The two interpolated fields (`active_alert_count`, `test_count`) are server-computed integers (`len(alerts)` / a dead always-0 field); no attacker-controllable string reaches `innerHTML`. Missing `escHtml` is hygiene, not a vuln. Left as-is.

---

## Adjusted / noted for later

- **web-6: WebSocket has no Origin check.** Real gap but LOW impact: job IDs are uuidv4 (non-enumerable) and no session-bound data rides the socket, so cross-site connections only get the public alert feed. Deferred (add an Origin allow-list on `/ws`).
- **The kill-switch UI** now prompts for the bearer token on the destructive toggle (step-up auth). Read-state polling is unaffected.

---

## Deploy gotchas learned this sweep (so you don't lose an hour)

1. **`nginx/nginx-ssl.conf` changes need `--force-recreate nginx`, not a reload.** The config is bind-mounted (`./nginx/nginx-ssl.conf:/etc/nginx/nginx.conf:ro`). rsync replaces the file via write-then-rename, changing its inode; the running container's mount keeps pointing at the *old* inode, so `nginx -s reload` re-reads stale config and silently does nothing. Recreate the container: `docker compose ... up -d --force-recreate nginx`. (Same inode-caching family as the upstream-DNS gotcha in CLAUDE.md.)
2. **`gh run list --limit 1` can hand back a cached/older run.** Match on `headSha` when watching a specific deploy, or you'll "verify" against a stale run and see old container uptimes.
3. **`.env.s3` secrets (e.g. `AUDIT_*`) are box-authoritative and not in git**: the deploy preserves them, but a fresh box needs them seeded before the audit viewer works.

---

## How it was verified (clean-state)
- `temp/smoke.sh` (reachability) + `temp/acid.sh` (async chat E2E to each agent) both green post-deploy.
- Per-fix checks: forged empty-key cookie → 401; no-auth `/api/recent` → 401; bearer → 200+data; allow-listed IP reaches viewer; brute-force query generates complete, non-truncated SQL; zero tracebacks across agents post-deploy.
- A truncation regression (`ath` SQL cut mid-literal on long multi-LIKE queries) was caught by acid *after* the first remediation deploy and fixed in `32979ad` (fixed thinking budget 512 + `max_tokens=4096` for SQL gen), then re-verified green.
