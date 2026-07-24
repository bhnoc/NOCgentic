# NOCgentic QA Sweep 4: Findings and Remediation

**Date:** 2026-07-24
**Scope:** Full codebase, targeting the bug CLASSES sweeps 1 to 3 did not systematically hunt. The per-file logic was already clean, so sweep 4 used four specialized hunters: deploy/config drift, cross-app contracts and concurrency, "lies about quality" (self-scoring paths), and a live-oracle that drives the running app and checks real output.

**Result:** 31 findings (1 flagged critical, 7 high, 14 medium, 9 low). The flagged critical was refuted on direct check. 7 highs plus 4 related mediums fixed. Deployed at `d5ce853`, verified from a clean state.

This sweep proved the "keep sweeping" instinct right. It found real security and correctness issues the earlier passes missed purely because they did not hunt these angles: a kill-switch that did not actually stop the data feed, an IP mask with a hole in it, agents that report high confidence on garbage, and a monitoring agent that reads a dead feed as all-clear.

## Refuted (the only "critical")

**cfg-1: "AWS creds never reach the containers."** The deploy-config hunter found no service has `env_file:` and nothing references `${AWS_ACCESS_KEY_ID}`, and concluded the whole `refresh-env-creds.sh` + `.env.s3` credential dance delivers creds to zero containers, so every Athena/S3 call should die. Direct check on the live container refuted it: `boto3.Session().get_credentials().method` returns `iam-role` and `has creds` is True. The containers get working credentials from the EC2 instance role via IMDS (boto3 handles the IMDSv2 token internally). The app works (acid 5/5). The `.env.s3` AWS injection is redundant theater, not a broken pipeline. Reclassified low: a misleading ritual and three docs that describe incompatible cred models, worth cleaning up, but not a broken app.

The lesson from the /qa playbook held: a confident static finding that contradicts a working live system is guilty until a live check proves it.

## Confirmed and fixed (highs)

**cc-1: the athena kill-switch did not stop the alert feed.** The emergency "kill athena" flag lives in the orchestrator and was only checked on the chat `/query` path. The live alert-feed sidebar pulls straight from `athena-hunter:8005/alerts/recent` via alertCache and never consulted the flag, so hitting the emergency stop silenced chat but kept broadcasting real Athena alerts to every connected client. Fix (per your decision that kill should freeze the feed): alertCache polls the orchestrator `/admin/killswitch` on its own 15s timer (bearer-authed with `ADMIN_BEARER_TOKEN`, added to the web-server service in compose), caches the killed state, and `dequeue()` returns nothing while athena is killed so the feed freezes. Fail-safe: if the token is unset or the check errors, the feed stays live and logs a warning, so a missing token can never silently freeze the feed.

**lo-1 / cc-2 (one bug): restricted IPs leaked through the alert `id`.** srcIp, dstIp, and description were masked (restricted subnets rewritten to the .69 decoy), but the composite `id` field (`alert_name|orig_h|ts`) was copied raw, so a restricted host leaked into the DOM and JSON. Live-confirmed: `10.220.199.121` appeared raw in an id while its srcIp was masked. Fix: run the id through the same `scrubString`. Verified live after deploy: zero restricted octets in any id.

**ql-1 / ql-2 / ql-3: every agent reported fake-high confidence on a parse miss.** Confidence is regex-extracted from the LLM answer, and each agent defaulted to a HIGH value (0.75 triage, 0.7 athena/thousandeyes) that was only overwritten on a regex match. A truncated answer (the confidence fence is the last thing generated, so it is the first casualty of a max_tokens cut) or one that scored confidence in prose kept the fake-high default. This inverts each prompt's own "confidence below 0.3 if data empty" instruction. Fix: default to a LOW 0.3 sentinel and log a warning on a miss, so an unparseable answer reads as low-trust.

**ql-4: a dead ThousandEyes feed read as all-clear.** `fetch_all_tests` wrapped its whole body in `except Exception: return []`, indistinguishable from a genuinely empty inventory, and the roll-up reported "no tests configured" with normal confidence. So an auth expiry, a 403 on the wrong account group, or a 5xx would tell the operator monitoring is fine. Sweep 3 fixed the blank-token and per-test-unknown branches but not this inventory-level one. Fix: `fetch_all_tests` returns `None` on failure; the roll-up treats None like the blank-token path (`monitoring_available: False`), never all-clear.

**lo-2: alert-triage answers contradicted their own data.** The structured `severity_breakdown` was normalized via `_norm_sev`, but the `prioritized_alerts` handed to the LLM carried raw numeric Suricata severity, so the model free-texted "severity 2 informational" against a breakdown that said 95 medium. Fix: normalize severity on the alerts before they enter the prompt, so the LLM sees the same buckets as the breakdown. (Run-to-run wording variance on top of that is LLM nondeterminism, not a code defect.)

**lo-3 (partial): scratchpad leak and truncation in ThousandEyes.** The answer was returned raw, so on a verbose/thinking response the model's pre-answer reasoning leaked to the user, and `max_tokens=2000` (the lowest of any agent) truncated it. Fix: strip everything before the first "## Answer" marker, and raise max_tokens to 4096 to match the others. Residual (accepted): the model sometimes still omits the unknown-count clause in its prose even though `unknown_count` is correct in the structured data. That is LLM noncompliance, not a data lie.

**cfg-2: `.env.example` was the dead OpenSearch config.** It listed `OPENSEARCH_*` and `THREAT_HUNTER_URL` and was missing every var the live Athena stack needs, yet `deploy.sh` tells a fresh-box operator to seed `.env.s3` from it, so a from-scratch deploy would boot broken. Fix: rewrote it to the live stack (all 26 compose vars, placeholders only, plain comments), removed the dead vars, and noted that containers get AWS creds from the instance role so `AWS_ACCESS_KEY_ID` does not belong there.

## Confirmed and fixed (mediums)

- **ql-7:** an unknown/NULL alert severity scored lowest and bucketed to "low," hiding it. Now it maps to a visible "unknown" bucket (scored medium) so it stays in the prioritized set and shows in the breakdown.
- **ql-8:** the same numeric Suricata severity mapped 1 to critical in athena-hunter but 1 to high in alert-triage. Aligned athena-hunter to alert-triage's `_norm_sev` (the canonical source): 1 to high, 2 to medium, 3 to low.
- **ql-9:** athena-hunter's total_alerts/flows/dns were counts of LIMIT-capped result sets presented as true totals. Now flagged "SAMPLED / at least N" when a cap is hit, so the number is not a lie about completeness.
- **cc-3:** the audit-monitor poll cursor could advance past a key that failed mid-batch while a later key succeeded, permanently skipping the failed key. Now the cursor stops at the last good key so the next poll retries.

## Deferred (low, by design)
The remaining lows are hygiene: the redundant `refresh-env-creds.sh` ritual (cfg-1, reclassified), a handful of config-doc mismatches (cfg-3 through cfg-8: OTEL endpoint default, unread S3_BUCKET var, the known IFS bug in deploy-agents.sh, a seed-s3.py arg mismatch), and SSE subscriber edge cases in audit-monitor (cc-4/cc-5, no leak, just a duplicate-span window). None affect the live app's correctness or security.

## Verified (clean-state)
Deploy `d5ce853` rebuilt the stack; smoke 5/5; acid 5/5 (cookie-carrying). Per-fix: no restricted IP in any alert id (was leaking `10.220.199.121`); thousandeyes answer now starts at "## Answer" with a real 0.6 confidence (scratchpad stripped, not the fake-high default); web-server has `ADMIN_BEARER_TOKEN` for the kill-switch check. TS build and Python parse clean across all edits; all new prose and comments em-dash-free.

## Operational note (not a sweep finding)
Mid-sweep, SSH to the box with the `~/.ssh/blackhat` key started returning "Permission denied (publickey)" though it worked earlier the same session and the key file is unchanged. The CI deploy runner (separate auth) is unaffected, and all verification was done over HTTPS. Worth checking the box's `authorized_keys` / sshd state when convenient; it did not block this sweep.
