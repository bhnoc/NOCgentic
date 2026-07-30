-- 0001_triage.sql — idempotent schema for NOCgentic triage hub + alert bucket state machine.
-- Run via store.init_schema() (globs *.sql sorted, so this runs after 0000_recall.sql).

-- ---------------------------------------------------------------------------
-- alerts — incoming IDS/security alerts with dedup and bucket lifecycle
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id               text PRIMARY KEY,
    dedup_key        text UNIQUE NOT NULL,
    bucket           text NOT NULL DEFAULT 'alerts',
    severity         int NOT NULL DEFAULT 0,
    source_ip        text,
    dest_ip          text,
    alert_type       text,
    signature        text,
    count            int NOT NULL DEFAULT 1,
    raw_data         jsonb,
    first_seen       timestamptz DEFAULT now(),
    last_seen        timestamptz DEFAULT now(),
    connector_source text,
    created_at       timestamptz DEFAULT now(),
    updated_at       timestamptz DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS alerts_dedup_key_idx
    ON alerts (dedup_key);

CREATE INDEX IF NOT EXISTS alerts_bucket_idx
    ON alerts (bucket);

CREATE INDEX IF NOT EXISTS alerts_severity_idx
    ON alerts (severity);

-- ---------------------------------------------------------------------------
-- bucket_transitions — append-only audit log of every state change
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS bucket_transitions (
    id                   text PRIMARY KEY,
    alert_id             text NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    from_bucket          text NOT NULL,
    to_bucket            text NOT NULL,
    reason               text,
    investigation_run_id text,
    transitioned_at      timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS bucket_transitions_alert_id_idx
    ON bucket_transitions (alert_id);
