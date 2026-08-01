# Athena refresh Lambda

Builds the Athena tables and views the agents query. Runs hourly on a schedule; not
part of the app's Docker stack and not touched by `git push` auto-deploy.

## What is here

| File | Purpose |
|------|---------|
| `athena_refresh_lambda_v6.py` | Handler. Discovers log types in S3, creates a table per type, loads incrementally by watermark, then rebuilds the derived views. |
| `derived_views.py` | Generates `alerts`, `uid_lookup`, `fuid_lookup` from Glue introspection. |
| `deploy.sh` | Package and upload. `--dev` targets the dev twin, `--dry-run` builds only. |
| `infra/*.json` | Captured function config, IAM policy, and schedule. Reference, not applied automatically. |

Two functions share one code artifact and differ only by environment:

- `blackhatnoc-athena-refresh`: the show, `blackhatnoc_glue`, `corelight/usa2026`
- `blackhatnoc-athena-refresh-dev`: dev, `blackhatnoc_dev_glue`, `corelight/dev/raw`

## Why the views are generated, not written by hand

The previous `alerts` / `uid_lookup` / `fuid_lookup` were created by hand in the
old AWS account. They never followed the account move, so every query against them
failed `TABLE_NOT_FOUND`, the caller swallowed the error, and the UI showed
"no alerts found" while 440k real alerts sat in the catalog.

They had also drifted where they did exist: `uid_lookup` covered 9 tables when 37
carry a `uid`, and `fuid_lookup` covered 1 when 6 do.

Membership now comes from the catalog on every run. Corelight only writes a log
type once it has seen that traffic, so `rdp` genuinely does not exist yet. When it
appears, the table is created and folded into the views on the same run.

## Alert sources

`alerts` unions five detection logs into one shape:

| `alert_type` | Table | Severity from |
|---|---|---|
| `suricata` | `suricata_corelight` | `alert_severity` int, 1 = high |
| `notice` | `notice` | `severity_name` |
| `ml` | `corelight_ml_results` | `predicted_probability` bucketed |
| `yara` | `yara_corelight` | always `high`, a rule match is a positive hit |
| `anomaly` | `anomaly` | `item_score` bucketed |

`anomaly` is **pre-wired but dormant**: the detector baselines the network before
emitting anything, so the table does not exist yet. It activates on the first run
after it appears, no code change.

`weird` is deliberately **not** an alert source. It is Zeek protocol telemetry at
~4.4M rows/day against suricata's 221k, and it buried every real IDS hit in a
recency-ordered feed. Still queryable directly and via `uid_lookup`.

## Footguns

**Severity strings must match the app.** `agents/athena-hunter/main.py::_normalize_severity`
maps anything outside `critical|high|medium|low|informational|unknown` to
`unknown`. Emitting `info` silently mislabels every row from that source.

**The anomaly log is shaped unlike the others.** No `id_orig_h`: the subject is
`original_entity`, a CIDR like `172.27.0.137/32`. `ipscope.is_in_scope` parses bare
addresses, so the `/32` form returns False even for an in-scope host, which would
redact every anomaly row. The view strips the suffix. Its `item_assoc_entities` is
a ~400-element array of mostly out-of-scope CIDRs and is deliberately not
projected, because `row_in_scope` scans every value on a row and would drop 100%
of anomaly rows.

**Config is required, not defaulted.** An earlier version fell back to the retired
account's bucket and database, so a missing env var pointed at infrastructure that
no longer exists, created nothing, and reported success. It now raises at import.

**A failed view keeps its previous definition.** `rebuild_derived_views` logs the
failure and continues, so the feed looks healthy while going stale. Always check
`derived_views.failed` is empty in the invocation response.

## Verify a deploy

```bash
./lambda/deploy.sh
aws lambda invoke --function-name blackhatnoc-athena-refresh \
  --payload "$(printf '{"date":"%s"}' "$(date -u +%F)" | base64)" \
  --profile ProductResearch-admins --region us-east-2 /dev/stdout
```

Expect `derived_views.rebuilt` to list all three and `derived_views.failed` to be
empty. Then confirm the app sees data:

```bash
curl -sk https://ng.bhnoc.com/api/v1/alerts/recent
```
