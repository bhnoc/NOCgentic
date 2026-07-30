-- 0002_memory.sql — idempotent schema for NOCgentic operational-context memory store.
-- Run via store.init_schema() (globs *.sql sorted, so this runs after 0001_triage.sql).

-- ---------------------------------------------------------------------------
-- agent_memory — persistent key/value memory with status lifecycle + versioning
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS agent_memory (
    id               text PRIMARY KEY,
    agent_slug       text NOT NULL,
    key              text NOT NULL,
    value            jsonb,
    context          text,
    category         text NOT NULL DEFAULT 'fact',
    memory_status    text NOT NULL DEFAULT 'draft',
    version          int NOT NULL DEFAULT 1,
    rationale        text,
    confidence_pct   int,
    run_id           text,
    usage_count      int NOT NULL DEFAULT 0,
    drift_score_pct  int,
    promoted_at      timestamptz,
    retired_at       timestamptz,
    created_at       timestamptz DEFAULT now(),
    updated_at       timestamptz DEFAULT now(),
    UNIQUE (agent_slug, key, version)
);

CREATE INDEX IF NOT EXISTS agent_memory_status_idx
    ON agent_memory (memory_status);

CREATE INDEX IF NOT EXISTS agent_memory_category_idx
    ON agent_memory (category);

CREATE INDEX IF NOT EXISTS agent_memory_agent_slug_idx
    ON agent_memory (agent_slug);

-- ---------------------------------------------------------------------------
-- memory_events — append-only audit log of every status transition
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS memory_events (
    id           text PRIMARY KEY,
    memory_id    text NOT NULL REFERENCES agent_memory(id) ON DELETE CASCADE,
    from_status  text,
    to_status    text NOT NULL,
    actor        text,
    at           timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS memory_events_memory_id_idx
    ON memory_events (memory_id);
