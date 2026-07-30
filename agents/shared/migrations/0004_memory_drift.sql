-- 0004_memory_drift.sql — idempotent schema for NOCgentic self-improving memory drift.
-- Adds outcome recording and proposal tracking tables to support drift detection sweep.
-- Run via store.init_schema() (globs *.sql sorted, after 0003_hunts.sql).

-- ---------------------------------------------------------------------------
-- memory_outcomes — per-run outcome recordings for each memory
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS memory_outcomes (
    id         text PRIMARY KEY,
    memory_id  text NOT NULL REFERENCES agent_memory(id) ON DELETE CASCADE,
    run_id     text,
    failed     boolean NOT NULL,
    at         timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS memory_outcomes_memory_id_idx
    ON memory_outcomes (memory_id);

-- ---------------------------------------------------------------------------
-- memory_proposals — shadow-mode proposals (what drift would do, pending human review)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS memory_proposals (
    id               text PRIMARY KEY,
    memory_id        text NOT NULL REFERENCES agent_memory(id) ON DELETE CASCADE,
    action           text NOT NULL,
    reason           text,
    drift_score_pct  int,
    status           text NOT NULL DEFAULT 'open',
    created_at       timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS memory_proposals_memory_id_idx
    ON memory_proposals (memory_id);

CREATE INDEX IF NOT EXISTS memory_proposals_status_idx
    ON memory_proposals (status);
