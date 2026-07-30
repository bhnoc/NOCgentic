-- 0003_hunts.sql — idempotent schema for NOCgentic proactive threat-hunting scheduler.
-- Run via store.init_schema() (globs *.sql sorted, runs after 0002_memory.sql).

-- ---------------------------------------------------------------------------
-- hunts — registry of MITRE-mapped threat hunt templates
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS hunts (
    id               text PRIMARY KEY,
    name             text NOT NULL,
    mitre_tactic     text NOT NULL,
    mitre_technique  text NOT NULL,
    hypothesis       text,
    hunt_query       text NOT NULL,
    enabled          boolean NOT NULL DEFAULT true,
    interval_hours   int NOT NULL DEFAULT 24,
    last_run_at      timestamptz,
    created_at       timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS hunts_enabled_idx
    ON hunts (enabled);

-- ---------------------------------------------------------------------------
-- hunt_runs — append-only record of every scheduled or manual hunt execution
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS hunt_runs (
    id                   text PRIMARY KEY,
    hunt_id              text NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    investigation_run_id text,
    verdict              text,
    severity             text,
    mitre_technique      text,
    summary              text,
    created_at           timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS hunt_runs_hunt_id_idx
    ON hunt_runs (hunt_id);

CREATE INDEX IF NOT EXISTS hunt_runs_created_at_idx
    ON hunt_runs (created_at);
