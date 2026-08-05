# QA sweep 9 — freeform search in chat

Scope: drive freeform, unscripted natural-language questions through the
live chat API the way a real NOC analyst types them at Black Hat, not the
starter chips or the alert-hunt chip flows already covered in sweep 1.
Covered: vague/slang phrasing, IOC lookups, country-name questions,
comparative/aggregate questions, and general "what's going on" questions.
Fixes committed to `fix/qa-sweep-live-findings`, not deployed.

## Method

Drove 23 freeform queries across two batches through `qa/drive_chat.py`
against `https://ng.bhnoc.com`, spanning country/geography questions
("who is talking to russia", "did we see any attacks from china or north
korea today"), vague/slang phrasing ("anythin sus goin on rn", "who's the
noisiest host"), comparative questions ("compare traffic volume between
general wifi and the training vlans"), and general security questions
("is anyone mining crypto on this network", "any beaconing patterns").

## Findings

**Country-name questions generate structurally broken SQL (confirmed,
fixed, high severity).** "who is talking to russia" produced
`id_resp_h LIKE '%ru%'` — a substring match against the IP ADDRESS STRING
for the letters "ru", which can never meaningfully match a country and
returns zero rows regardless of real traffic. Confirmed the real column is
`conn.remote_country` (holds 2-letter ISO codes) by cross-checking a sibling
query ("list every unique country") that correctly used it and returned real
codes (US, SG, GB, FR, NL). Reproduced the identical bug twice more with
"show connections to iran" (`id_resp_h LIKE '%ir%'`) and "did we see any
attacks from china or north korea today" (`id_orig_h LIKE '%cn%' OR
id_orig_h LIKE '%kp%'`) — all three asked before the fix deployed, so this
is a systemic gap, not a one-off. Root cause: the SQL_GEN_PROMPT has a
worked example for org-NAME lookups (`remote_organization LIKE '%Zoho%'`)
but no equivalent example for country-NAME lookups against the differently-
shaped `remote_country` column, so the model generalized the org pattern to
a column it doesn't fit. Fixed by adding an explicit rule and worked
examples (Russia→RU, China→CN, Germany→DE) plus a direct warning against
LIKE-matching an IP string for a country name.

This bug is invisible in the UI: the answer read as a clean, confident "No
activity to Russia in the last hour" — a query that ran, found nothing, and
got the honest low-confidence phrasing from an earlier sweep's fix. Nothing
about the rendered answer signals that the query itself was incapable of
finding anything.

**"Is anyone mining crypto" hallucinates a mining claim from an unrelated
alert name (confirmed, fixed, high severity).** The keyword search correctly
matched `%crypto%|%mining%` against alert names and returned `Viz::CustomCrypto`
(288 hits, actually a TLS cipher-negotiation notice) and `ET GAMES MINECRAFT`
(3 hits, a video game) as lexical false positives alongside one genuine hit
(a real crypto-RAT C2 domain, 6 hits). The model correctly dropped the
Minecraft row but wrote `Viz::CustomCrypto` into the final answer as
supporting evidence for "Active cryptocurrency mining ... is occurring,"
with a specific host to isolate and IPs to block. Fixed by adding an
explicit lexical-vs-semantic distinction to the SYSTEM_PROMPT, naming both
false-positive patterns from this exact incident as worked examples, and
instructing the model to say the search found nothing genuinely on-topic
rather than reach for the closest-sounding name.

**"anythin sus goin on rn" fabricates a full incident from zero alert rows
(confirmed, fixed, critical severity).** `total_alerts: 0` in the data, yet
the alert-triage answer stated "CONFIRMED suspicious data exfiltration
activity," named 10 specific host IPs none of which appear anywhere in the
shown data, invented a per-host alert count ("192.168.157.197 generated 73
alerts across 7 distinct signatures"), and issued "Block X" / "Pivot on
uid=Y" instructions for uids that don't exist in the payload — while the
rendered "## Key Entities" section was a literal empty bullet (`- ` with
nothing after it), which should have been the tell that nothing backed this.
Root cause: the existing "when triage_data is empty, say so" rule is
ambiguous about WHICH field must be empty — `flows`/`dns`/`session_context`
were genuinely non-empty (99 flows, 7 DNS queries) even though
`prioritized_alerts` (the actual alert list) was empty, and the model
apparently used the non-alert context to construct a plausible-sounding
narrative instead of recognizing there were zero alerts to validate against.
Fixed by making the rule specific to `prioritized_alerts` explicitly, stating
that flow/DNS/session context is supporting context for an alert and must
never be turned into a verdict, a named host, a count, or a uid that isn't
literally present in the data.

This is the most severe finding across all sweeps so far: a completely
fabricated CONFIRMED verdict, complete with actionable containment
instructions naming real-looking IPs, on a query that had no alert data
behind it at all. This is exactly the kind of answer that gets acted on.

## Everything else driven, and found no defect in

- **Direct IOC lookup** ("whats the deal with 192.168.144.107"): grounded,
  specific answer citing real alert counts and byte volumes for that exact
  host.
- **Aggregate/comparative questions** ("compare traffic volume between
  general wifi and the training vlans", "who's using the most bandwidth per
  device on average", "top 5 destinations by data volume", "how many unique
  devices have we seen today"): all returned real, internally-consistent
  numbers with correctly-labeled evidence.
- **Slang/vague phrasing that isn't also a false-alarm trigger** ("who's the
  noisiest host", "what happened between 2pm and 3pm today"): parsed
  correctly into a reasonable interpretation and answered with real data.
- **"Show me every alert mentioning ransomware"**: correctly reported no
  ransomware-named alerts among the rows examined, properly hedged rather
  than overclaiming.
- **"Any beaconing patterns"**: cited real, non-false-positive alert names
  (CrowdStrike Winnti C2, a real crypto-RAT C2 domain) with real hit counts;
  correctly dropped the same kind of lexical false positives (a file-sharing
  domain, a QR-code generator domain) that the crypto-mining case failed to
  drop. Grounded, though the confident tone on IDS alert names that may be
  red-team/training-network artifacts (per sweep 1's finding on this venue)
  is a calibration question, not a fabrication — left alone this sweep.

## Verification

`ops/run-tests.sh`: 1444 Python + 270 TypeScript tests, all green, no
regressions across all three prompt-text fixes.

All three fixes are LLM-prompt-guided (not deterministic code), so static
verification (syntax checks, the existing test suite) cannot fully confirm
the fixed behavior the way a live model call can. Recommend re-running the
same failing queries ("who is talking to russia", "is anyone mining crypto
on this network", "anythin sus goin on rn") against a deployed copy of this
branch before considering these closed, the same way every prior sweep's
fixes were re-verified live after deploy.

## Recommendation

The alert-triage fabrication finding is the highest-severity thing found in
any sweep so far — a security tool inventing a confirmed incident with
actionable remediation steps from zero underlying alert data. Recommend
deploying and re-verifying all three fixes live as the next step, with
particular attention to re-testing the exact "anythin sus goin on rn" query
(or another phrasing that returns zero alerts alongside non-zero flow/DNS
context) to confirm the fabrication is actually gone, not just less likely.
