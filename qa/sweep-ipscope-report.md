# QA sweep — IP scope allowlist (2026-07-31)

Branch `feat/ip-scope-allowlist`. Sweep of the default-deny IP scope work: the new
`agents/shared/ipscope.py` policy, in-code enforcement at the Athena boundary, and the
redaction wiring across all four agents plus telemetry and trace-export.

## Posture

Findings validated by local repro against `tests/python/.venv` and by building the real
agent containers. Nothing was run against the shared AING box. Baseline before the sweep:
124 python tests, 23 vitest, UI gate green.

## Fixed

**Alert IDs collided, dropping alerts from the feed (critical).**
`agents/athena-hunter/main.py` redacted `orig_h` before using it to build `alert_id`, so
every out-of-scope host produced the same id. The UI dedups on `data-id`
(`static/index.html`), so all but the first alert of a given signature and timestamp were
silently discarded. In a SOC that is lost incidents, not a cosmetic bug. Introduced by the
scope change itself, found by two independent hunters and confirmed by probe.

Fixed by deriving identity from a sha256 prefix of the raw host. The raw address could not
be used directly: the id is written to a `data-id` DOM attribute, so it would have re-leaked
the exact value redaction removed, readable in devtools. Gate:
`tests/python/test_alert_id_identity.py` (imports the real `_athena_row_to_alert`; 2 of its
6 checks fail against the pre-fix code).

**LIKE and regexp prefixes bypassed both enforcement layers (critical).**
`SELECT COUNT(*) FROM conn WHERE id_orig_h LIKE '192.168.1.%'` contains no full dotted
quad, so the literal-only scope check in `sanitize_sql` saw nothing to reject. The row
filter did not catch it either, because a `COUNT(*)` row carries no address column. The
query returned real aggregates about an out-of-scope subnet. Same for
`regexp_like(id_orig_h, '^10\.0\.')`.

Fixed with `ipscope.prefix_is_out_of_scope()`, which blocks a partial dotted prefix only
when the entire block it covers is out of scope. In-scope prefixes (`10.220.40`) and public
ones (`45.83.193`) stay queryable. Validated against the whole real SQL corpus in this
repo: 24 extracted statements, zero false rejects.

**The row filter's field allowlist was defeated by aliasing (critical).**
`row_in_scope()` inspected a fixed list of column names. `agents/alert-triage/main.py:413`
really does `SELECT id_orig_h as ip`, and `row_in_scope({'ip': '10.0.1.63'})` returned True.
It also missed addresses embedded in free text such as a DNS `answers` column.

Replaced the name allowlist with a scan of every value on the row. This needs no
maintenance when a query adds a column or an alias, and it catches IPs in prose.

**Dotted non-addresses were rejected as out-of-scope IPs (medium).**
`is_in_scope()` returns False for anything unparseable, so `sanitize_sql` rejected a value
like `'1.2.3.400'` with "Out-of-scope IP in query". `redact_text` already guarded against
this; `sanitize_sql` did not. Now both parse before judging.

## Deferred, with reasons

**Demo and seed data is entirely out of scope (high, product).** All 9
`scripts/seed-s3.py` `INTERNAL_IPS` and 4 of 6 hardcoded UI demo alerts are out of scope, so
any environment without live conference data renders `[OUT-OF-SCOPE-IP]` everywhere. This is
a product decision about what demo data should look like, not a code defect, and it needs
the NOC lead's call before rebasing fixtures onto conference ranges.

**Documented example queries now rejected (high, docs).** Example IPs in
`docs/Athenaguide.md.md`, `API_INSTRUCTIONS.md` and `SETUP.md` are out of scope, so
copy-pasting them raises the scope ValueError. The rejection is correct behavior; the docs
need updating to in-scope examples.

**IPv6 is not redacted (medium).** `redact_text` has no IPv6 pattern, so `fd00::1` and
`fe80::` addresses pass through free text unredacted. `is_in_scope` classifies IPv6
correctly (all v6 is out of scope, since the supplied allowlist is IPv4-only), so this is a
pattern gap not a policy gap. Deferred pending confirmation of whether the conference has
IPv6 in scope at all.

**Raw query and response text ships to telemetry unredacted (critical, pre-existing).**
`telemetry.py`'s `_SENSITIVE_ATTR_HINTS` does not include `query.text`, `response.text` or
`classification.reasoning`, all of which are stamped on spans by all four agents and
exported to Manifold OTLP, the S3 trace archive, and console logs. Verified: those keys
return False from `_is_sensitive_attr`. Predates this branch (confirmed against `HEAD~1`),
so it is out of scope for this diff, but it is the most serious open item in the sweep.

**User-facing sanitizer does not strip secrets (high, pre-existing).**
`sanitize_output_text()` redacts IPs, zones and service names but never applies the
secret/password/API-key patterns that the LLM-input `sanitize()` uses. A credential in an
error message reaches the browser intact. Confirmed by probe in a real container. Also
predates this branch.

## Refuted

Zero-padded octets (`010.000.001.063`) were reported as a full-leak vector. They are not
valid addresses: `ipaddress.ip_address()` rejects them, so Athena would never emit that
form and there is nothing to leak.

Subnet arithmetic was independently re-derived and is correct: 118 networks, the
`10.220.30.0/25` half range, the `192.168.128.0/18` span, and the `.73` exclusion.

## Verification

148 python tests (up from 124), 23 vitest, UI gate green. All four agent images rebuilt
from scratch and import-checked, with the fixes exercised inside the container rather than
only against the local venv. Every new gate was confirmed to fail against the pre-fix code:
the SQL gates go 5 red, the alert-id gate 2 red.

One gate was rewritten during the sweep. The first version of `test_alert_id_identity.py`
reimplemented the id logic instead of importing it, so it passed against the buggy code too.
It now loads the real module by path.

## Follow-up (2026-07-31, same day)

Two of the deferred items were resolved after the NOC lead's decision.

**Manifold telemetry stays unredacted by design.** The `query.text` / `response.text` /
`classification.reasoning` span attributes reaching the OTLP endpoint and S3 trace archive
in full is intended: those are the internal investigation record, not user-facing output.
Not a finding. Do not "fix" this in a later sweep. Credentials are still scrubbed on that
path via `telemetry.py`'s own patterns, which are already hash-aware.

**Credentials no longer reach the browser.** Added `agents/shared/credscrub.py` as the
single credential scrubber and wired it into both browser-facing egress points:
`sanitize_output_text()` in the orchestrator, and `_athena_row_to_alert()` in athena-hunter
(the alert feed bypasses the orchestrator entirely). The four agents' `sanitize()` now call
it too, which fixed a latent defect: their local `_RE_SECRET_TOKEN` matched any 40+
base64-ish run including entirely-hex tokens, so it destroyed MD5/SHA-1/SHA-256 file
hashes, exactly the IOCs an analyst needs. The shared pattern carves out all-hex tokens.

**Demo data rebased onto conference ranges.** `scripts/seed-s3.py` `INTERNAL_IPS` and the
four out-of-scope UI demo alerts now use in-scope 10.220.x addresses. `randomIp()` in the
demo ticker was left alone: it generates public addresses that play the external attackers,
and those are shown by design.

Gates: `tests/python/test_credscrub.py` (16 checks, including that hashes survive) and
`tests/python/test_demo_data_in_scope.py` (3 checks). Both confirmed to fail against the
pre-fix state.

Two footguns worth remembering. The module was first named `secretscrub.py`, which
`.gitignore`'s `*secret*` credential-safety rule silently swallowed — the file existed,
tests passed locally, and `git status` showed nothing. Renamed to `credscrub.py`; do not
weaken that ignore rule. And the first pass added the import to only two of the four
agents; the local suite caught it, but only because the tests import the real modules.
