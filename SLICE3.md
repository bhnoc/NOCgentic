# SLICE 3 — Triage hub + alert bucket state machine (level9000)

## Contract
- **Goal:** An autonomous triage hub: alerts land in a queue, a worker runs the investigator loop
  per alert, and files a verdict that moves the alert through a bucket state machine — every move
  audited in bucket_transitions and linked to the investigation run that decided it. Analysts see
  a priority-grouped queue and can approve/override/feedback.
- **Acceptance (observable, via API):**
  1. `POST /alerts` (single or batch) → alert stored, deduped on `dedup_key` (repeat → count++ not dup),
     starts in bucket `alerts`.
  2. `GET /triage/queue?bucket=&severity=` → alerts grouped/filterable by bucket + severity, ordered
     by severity desc then last_seen.
  3. `POST /triage/{alert_id}/investigate` → moves alert `alerts`→`validating`, invokes the investigator
     service (`INVESTIGATOR_URL/investigate`) with a query built from the alert, then files the verdict:
     high-signal/threat → `validated_true_positive`; benign → `validated_false_positive`. Records TWO
     bucket_transitions (alerts→validating, validating→<verdict>), each linked to the investigation run_id.
  4. `GET /triage/{alert_id}` → alert + its full transition history + the linked investigation run_id(s).
  5. Analyst override: `POST /triage/{alert_id}/transition {to_bucket, reason}` → validated move with
     audit row. Guard: reject transitions not allowed by the state machine (e.g. can't go straight
     alerts→validated_true_positive without validating) unless `force=true` (analyst authority).
  6. Bad transition (unknown bucket, or illegal edge without force) → 4xx with a clear reason, no state change.
- **Done:** acid green from clean; triage worker driven offline by injecting a fake investigator
  client (no real investigator/Athena/Gemini needed). Live HTTP smoke against the container.

## Bucket state machine (ported/trimmed from VR bucket_type)
Buckets this slice: `alerts` (new), `validating` (worker running), `validated_true_positive`,
`validated_false_positive`, `validated_bad_hygiene`, `tuning_queue` (noisy FP → rule tuning),
`dismissed`. Legal edges (code-enforced in a transition guard):
- alerts → validating, dismissed
- validating → validated_true_positive, validated_false_positive, validated_bad_hygiene, alerts (retry)
- validated_false_positive → tuning_queue, dismissed
- validated_true_positive → dismissed (after response)
- any → dismissed
`force=true` (analyst override) bypasses the edge check but STILL writes an audit row with reason.

## Architecture — new service `triage` (port 8008), reuses shared + calls investigator
- New migration `agents/shared/migrations/0001_triage.sql`: `alerts` + `bucket_transitions` tables
  (ported columns above; bucket as TEXT + a CHECK constraint or just TEXT validated in code — use TEXT
  + code validation to avoid enum-migration pain). Indexes: unique(dedup_key), (bucket), (severity).
- store.py: ADD alert/transition helpers — `upsert_alert(...)->id, get_alert(id), list_alerts(bucket?,severity_min?)`,
  `transition_alert(alert_id, to_bucket, reason, investigation_run_id?, force=False)->dict` (validates edge,
  writes bucket_transitions row, updates alerts.bucket), `alert_transitions(alert_id)->list`. Reuse the pool.
  init_schema() must run BOTH migrations (0000 + 0001) idempotently — generalize it to glob migrations/*.sql sorted.
- `agents/triage/main.py` (FastAPI :8008): endpoints above. The investigator call goes through an
  injectable client seam `InvestigatorClient` (prod: httpx POST to INVESTIGATOR_URL/investigate; test: fake
  returning a scripted finding). Verdict mapping is CODE (finding.verdict/high_signals → bucket), not LLM.

## Pinned bits
- `build_alert_query(alert)->str`: deterministic NL question from alert fields ("Investigate <signature>
  from <source_ip> to <dest_ip> in the last N hours; is it a real threat?"). CODE.
- Verdict→bucket map (CODE): finding.verdict=="threat" or high_signals nonempty → validated_true_positive;
  else validated_false_positive. severity carried from alert.
- The transition guard is the load-bearing deterministic piece — test it hard (legal edges pass,
  illegal rejected, force overrides + still audits).

## Tests — tests/python/test_triage.py (PG skip-guard, fake InvestigatorClient)
Covers acceptance 1-6. Dedup, queue grouping/order, full investigate→verdict→two-transitions flow with
linked run_id, override, and the state-machine guard (legal/illegal/force). No external services.

## Model routing: sonnet-5 (state machine + service). Judge at opus only if it misses.
