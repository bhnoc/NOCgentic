# Root-cause service — real Athena schema notes (ground truth for the integrator)

Source: docs/DATA-SCHEMA.md + agents/athena-hunter/main.py system prompt.

- DB `blackhat_pope_logs`, workgroup `blackhat-pope-dev`, region us-west-2. Reuse `agents/shared/athena_client.py::execute_query(sql)`.
- **Timestamps are Unix epoch FLOATS** (e.g. `1776752541.431893`), column `ts`.
- **Partition column is `dt`** (string date, e.g. '2026-07-30'). ALWAYS filter on `dt`. Use athena_client date helpers (`today_partition`, `date_partitions`).
- Column names are FLATTENED (dots → underscores): `id_orig_h`, `id_resp_h`, `id_orig_p`, `id_resp_p`.

## Tables for anomaly detection ("novel/rare signal" = the stack-trace analogue)
- `suricata_corelight`: `uid, id_orig_h, id_resp_h, id_orig_p, id_resp_p, alert_action, alert_signature, alert_category, alert_severity (INT, 1=highest), alert_signature_id, service, community_id`. This is the primary anomaly surface. High-signal = alert_severity <= 2 and NOT an "ET INFO" signature.
- `notice`: `note` (enum e.g. SSL::Invalid_Server_Cert), `msg` (human text), `actions`. Zeek detection notices.
- `weird`: `name` (anomaly type), `addl` (details), `notice` (bool). Protocol anomalies.

## Anomaly detection query shape (code-owned, deterministic — NOT LLM)
Time-series bucket of alert volume per signature over the window; a "spike" = a bucket whose
count exceeds mean + K*stddev of the series, OR a signature appearing that wasn't in the prior
baseline window. Group by alert_signature. Example skeleton (bind dt + window in code):
```sql
SELECT alert_signature,
       date_trunc('hour', from_unixtime(ts)) AS bucket,
       count(*) AS n
FROM suricata_corelight
WHERE dt IN (<partitions>) AND alert_severity <= 2
  AND alert_signature NOT LIKE 'ET INFO%'
GROUP BY 1, 2
ORDER BY 2
```
Fetch the raw spiking rows (for Drain clustering) with a second query filtered to the spiking
signature + bucket window.

## Deploy-marker correlation (code-owned)
`deploy_markers` table (in Postgres, not Athena) holds ts + kind + ref + commit_sha. After locating
the spike window [t0,t1], call `store.markers_near(t0 - slack, t1)`. If a marker falls in/just-before
the window, the finding's root_cause references it. This is the "correlate error spike with recent
code push" pattern from the user's brief, grounded in NOC deploy events (sensor config pushes,
rule updates, infra changes) rather than app commits.

## AnomalySource seam
The service defines a Protocol `AnomalySource` with `detect(window_hours) -> AnomalyReport` and
`fetch_events(signature, t0, t1) -> list[str]`. Prod impl (`AthenaAnomalySource`) uses execute_query;
tests inject a `FixtureAnomalySource` returning canned rows so acid runs with no AWS creds.
