-- 0000_recall.sql — idempotent schema for NOCgentic recall / agentic trace store.
-- Run via store.init_schema() or directly: psql $PG_DSN -f 0000_recall.sql

-- pgvector extension (must come first; no-op if already installed)
CREATE EXTENSION IF NOT EXISTS vector;

-- ---------------------------------------------------------------------------
-- log_templates — drain-clustered event templates with pgvector embeddings
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS log_templates (
    id          text PRIMARY KEY,
    template    text UNIQUE NOT NULL,
    sample      text,
    mask_keys   jsonb,
    source      text,
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now(),
    count       int NOT NULL DEFAULT 1,
    embedding   vector(768)
);

-- HNSW cosine index for fast ANN on log_templates.embedding
CREATE INDEX IF NOT EXISTS log_templates_embedding_hnsw
    ON log_templates USING hnsw (embedding vector_cosine_ops);

-- ---------------------------------------------------------------------------
-- incidents — resolved incidents with embeddings for recall
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id            text PRIMARY KEY,
    title         text,
    summary       text,
    root_cause    text,
    resolution    text,
    template_id   text,
    embedding     vector(768),
    created_at    timestamptz NOT NULL DEFAULT now(),
    resolved_at   timestamptz,
    deploy_marker text,
    commit_sha    text,
    status        text NOT NULL DEFAULT 'resolved'
);

-- HNSW cosine index for fast ANN on incidents.embedding
CREATE INDEX IF NOT EXISTS incidents_embedding_hnsw
    ON incidents USING hnsw (embedding vector_cosine_ops);

-- ---------------------------------------------------------------------------
-- deploy_markers — code-push / config-change events for correlation
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS deploy_markers (
    id         text PRIMARY KEY,
    ts         timestamptz NOT NULL,
    kind       text,
    ref        text,
    commit_sha text,
    note       text
);

CREATE INDEX IF NOT EXISTS deploy_markers_ts_idx
    ON deploy_markers (ts);

-- ---------------------------------------------------------------------------
-- agent_runs — one row per agentic investigation run
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS agent_runs (
    id          text PRIMARY KEY,
    kind        text,
    input       jsonb,
    output      jsonb,
    status      text NOT NULL DEFAULT 'running',
    started_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    token_usage jsonb
);

-- ---------------------------------------------------------------------------
-- agent_events — append-only reasoning trace (event sourced)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS agent_events (
    id         bigserial PRIMARY KEY,
    run_id     text NOT NULL REFERENCES agent_runs(id),
    seq        int NOT NULL,
    ts         timestamptz NOT NULL DEFAULT now(),
    event_type text,
    data       jsonb
);

-- st-2: drop old non-unique index (replaced by unique variant below)
DROP INDEX IF EXISTS agent_events_run_seq_idx;

-- UNIQUE constraint so a racing duplicate seq errors loudly instead of silently corrupting order
CREATE UNIQUE INDEX IF NOT EXISTS agent_events_run_seq_uniq
    ON agent_events (run_id, seq);
