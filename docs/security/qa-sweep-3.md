# NOCgentic QA Sweep 3: Findings and Remediation

**Date:** 2026-07-24
**Scope:** The validated med/low backlog carried from sweeps 1 and 2, plus stale-doc cleanup after the sweep-2 threat-hunter removal.
**Going in:** no live criticals or highs were open. This sweep is hardening, hygiene, and honesty.

**Result:** 36 backlog findings triaged. 4 were already dead (threat-hunter removal in sweep 2 disposed of them). 32 live findings fixed across web-server, shared, specialists, orchestrator, and tools. `scripts/seed-opensearch.py` removed. Deployed at `1fd9e44`, verified from a clean state.

---

## Fixed

### web-server (public surface)
- **web-5 (IDOR):** jobs are now bound to the creator's `bh_sid` session cookie. `GET /api/v1/chat/:id` returns 404 (not 403, no existence oracle) for a non-owner. Proven live: owner session gets 200, a different session gets 404. Cookieless clients are treated as unowned and can still read (so curl works), which is the deliberate trade-off.
- **web-6 (WS Origin):** `/ws` closes any handshake whose Origin is present and not `https://aing.bhnoc.com` with code 1008. Proven with a raw WS client: `evil.example` gets a 1008 close, the real origin does not. (curl shows 101 then a close it can't display, which is why a proper WS client was used to verify.)
- **web-9 (cookie):** `bh_sid` is now `HttpOnly` + `Secure` + `SameSite=lax`. The UI uses a separate localStorage id for its own identity, so nothing broke. Proven via the `set-cookie` header.
- **web-10 (headers):** hand-rolled CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` (no helmet dependency added). CSP allows `'unsafe-inline'` for script/style because the first-party UI uses inline handlers; Google Fonts and `ws:`/`wss:` are allowed. Proven present on the live response; the UI still renders.
- **web-101 (dead WS fast-path):** the server never broadcast `job_update` on completion, so the client's WS fast path was dead and polling was already the only render path. Removed the dead code on both sides so the behavior is honest.
- **web-102 / web-103:** dropped an always-blank `dstPort` field from the alert render; the 400 for invalid input now returns a generic message with the Zod detail logged server-side (was leaking the schema).

### shared
- **sh-101:** added `sanitize_like_value()` (escapes `%`, `_`, `\` and requires an `ESCAPE` clause) and pointed the two real LIKE call sites (`query_dns`, `query_ssl`) at it. `sanitize_value` equality behavior unchanged.
- **sh-102:** the `GEMINI_MODEL` code default was `gemini-3.1-pro-preview` while every deployed service pins flash-lite. Changed the code default to `gemini-3.5-flash-lite` so an unset env var can't silently drop callers onto the expensive pro model (which also skips the flash-lite thinking-budget clamp).
- **sh-103 / sh-107:** the 500-row result cap and MAX_TOKENS truncation were both silent. Both now log a warning so truncation is visible.
- **sh-106:** `date_partitions` stopped over-generating a trailing partition day.
- **sh-111:** the secret-redaction regex was nuking hex hash IOCs (64-char SHA-256). Added a negative lookahead so pure-hex strings survive while real base64 secrets are still redacted.

### specialists
- **spec-101:** thousandeyes-analyst now sanitizes the query and fences untrusted telemetry, matching alert-triage.
- **spec-104:** alert-triage's `llm_triage` catches broad exceptions (429/5xx/timeout) and degrades gracefully instead of throwing a 500.
- **spec-107:** the parsed `severity` filter is now actually applied ("show only critical alerts" was being silently ignored). Uses the sweep-2 `_norm_sev` normalizer.
- **spec-110:** a blank ThousandEyes token now reports "monitoring not configured" instead of `healthy: True`. Same false-all-clear class as the sweep-2 spec-109 fix.
- **spec-112:** the keyword filter returns nothing on zero matches (it was returning the full unfiltered set, inverting intent).

### orchestrator + tools
- **to-102:** the background hint task is retained so asyncio can't garbage-collect it mid-run.
- **to-103:** removed the no-op `verify=False` from the internal `http://` agent calls (there's no TLS to verify on the internal network).
- **to-104:** the user query is now sanitized before going into the hints prompt (sweep 2 only sanitized the answer).
- **to-105:** the classifier system prompt now explicitly treats the query as untrusted and says injection attempts must be classified normally, not obeyed.
- **to-106:** trace-export redacts client IPs, sessions, prompts, and SQL by default, with a `--raw` opt-out.
- **to-107:** `/api/recent?limit<=0` returns empty instead of the whole buffer.
- **to-110:** redate_slice shouts loudly (stderr + end-of-run summary) if a partition is cleared but the insert fails, so a half-done demo reseed can't fail silently.
- **to-108 / to-116:** doc and comment corrections.
- **Removed `scripts/seed-opensearch.py`** (dead OpenSearch tooling, zero live references), which disposed of to-112/113/114/115.

### docs
Updated README, design.md, DATA-SCHEMA.md, MANIFOLD_INTEGRATION.md, the audit-monitor README, and the deploy/ops skills to drop the removed threat-hunter and mark agent ports internal-only. Historical logs (PROGRESS, NEWDIRECTION_PROGRESS, After-Action) were annotated with dated notes rather than rewritten. Fixed the orchestrator module docstring. All new prose is em-dash-free.

---

## The one that bit back: verifying the fix, not just the finding
The web-5 IDOR fix binds each job to its creator's session cookie. That's correct, but `qa/acid.sh` submitted a chat job and then polled it without carrying any cookie, so the poll started returning 404 and acid reported 3 chat failures. For a few minutes that looked like the deploy broke the chat pipeline.

It hadn't. The pipeline works: a cookie-carrying client (POST then poll with the same jar, exactly what the browser does) gets a clean `done` response from every agent. The fix changed the client contract: a correct API caller must now persist the session cookie across POST and GET. The bug was in the test harness, not the app. Fixed `qa/acid.sh` to carry a cookie jar (`-c`/`-b`), and it went 5/5 green.

Lesson, now baked into the `/qa` command: judge the fix as hard as the finding, and distrust a red result as much as a green one until you know which side the bug is on.

---

## Verified (clean-state)
7 containers healthy after rebuild; smoke 5/5; acid 5/5 (cookie-carrying). Per-fix live checks: IDOR owner 200 / foreign 404; WS foreign-origin 1008 close; `bh_sid` HttpOnly; CSP + security headers present; all three agents answer.

## Still deferred (by design, low value)
- **web-4:** jobStore has no eviction/TTL. Slow memory growth over a long run, recovered by a container bounce. Candidate for a sweep 4 if you want it airtight for a multi-day event.
- **sanitize_sql residual:** a comment-less `OR 1=1` still parses. It sits behind the LLM and read-only single-DB Athena creds, so the blast radius is cross-table disclosure within `blackhat_pope_logs`, not writes.
