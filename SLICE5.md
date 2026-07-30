# SLICE 5 — Operational-context memory / semantic DB (level9000)

## Contract
- **Goal:** A persistent operational-memory store the platform learns and reuses: facts about the
  environment (test IP ranges, critical hosts, approved scanners, maintenance windows) with a
  status lifecycle (draft→candidate→active→retired), confidence, versioning, and usage tracking.
  Active memories are injected (sanitized) into the investigator's system prompt so investigations
  get smarter over time and false positives drop. Ported from VR agent_memory. NO embeddings — key/value + stats.
- **Acceptance (observable, via API + unit):**
  1. `POST /memory {agent_slug,key,value,category,context,rationale,confidence_pct}` → upserts a memory
     (draft). Same (agent_slug,key) again → new VERSION (version++), not a duplicate row's dup.
  2. Lifecycle: `POST /memory/{id}/promote` draft→candidate→active (one step each, records promoted_at
     + a memory_event); `POST /memory/{id}/retire` →retired (records retired_at). Illegal jumps rejected.
  3. `GET /memory?agent_slug=&status=&category=` lists, ordered by confidence desc, usage desc, recency.
  4. `GET /memory/context?agent_slug=` → the ACTIVE memories formatted as a promptable text block,
     ranked (confidence→usage→recency), capped at N (MAX_INJECTED=40), split into "Learned Improvements"
     (prompt_refinement) and "Operational Context" (fact/preference/lesson_learned). usage_count bumped.
  5. SANITIZATION (the #1 gotcha): memory value/context is sanitized before it can enter a prompt —
     strip/deny prompt-injection patterns ("ignore previous instructions", role hijacks), cap length,
     drop control chars. `build_memory_block` must never emit an un-sanitized memory. Unit-tested with
     malicious memory content → the injection text is neutralized/dropped.
  6. INTEGRATION: the investigator's system prompt includes the memory context block for its agent_slug
     (fetched via the memory service or store directly). Unit-tested: with a seeded active memory
     ("10.220.99.0/24 is the approved scanner range, ignore its scans"), the investigator's initial
     system prompt contains that operational fact (sanitized). Proven with the FixtureProvider (capture
     the messages passed to provider.chat).
- **Done:** acid green from clean (new test_memory.py + investigator integration test); container smoke.

## Architecture — extend store + new `memory` service (port 8009); investigator consumes it
- New migration `agents/shared/migrations/0002_memory.sql`: `agent_memory` (ported cols: id, agent_slug,
  key, value jsonb, context, category, memory_status, version, rationale, confidence_pct, run_id,
  usage_count, drift_score_pct, promoted_at, retired_at, created_at, updated_at; UNIQUE(agent_slug,key,version))
  + `memory_events` (id, memory_id, from_status, to_status, actor, at). Indexes on status, category, agent_slug.
- store.py additions: MEMORY_STATUSES + MEMORY_LIFECYCLE edges (draft→candidate→active, any→retired),
  `upsert_memory(...)` (version bump on existing agent_slug+key), `get_memory`, `list_memories(...)`,
  `transition_memory(id, to_status, actor)` (guard + memory_events row + promoted_at/retired_at stamps),
  `active_memories(agent_slug, limit)`, `bump_memory_usage(ids)`.
- NEW `agents/shared/memory_prompt.py`: `sanitize_memory_text(s)->str` (deny-list regex for injection,
  length cap, control-char strip) + `build_memory_block(memories)->str` (ranked, split, sanitized, capped).
  Pure + deterministic + unit-tested HARD (this is the security boundary).
- NEW `agents/memory/` (FastAPI :8009): the endpoints above. verdict/promotion decisions are analyst/API
  driven this slice (no auto-drift engine yet — that's a later slice; keep confidence/drift columns for it).
- investigator/main.py: BEFORE building the initial messages, fetch active-memory context for agent_slug
  "investigator" (via store.active_memories + build_memory_block, in-process — no HTTP dependency so the
  investigator doesn't hard-depend on the memory service) and prepend it to the system prompt. Guarded:
  if the memory table/its rows are absent, the block is empty and the investigator behaves as before.

## Tests
- tests/python/test_memory.py (PG skip-guard): upsert+version, lifecycle guard (legal/illegal/retire),
  list ordering, context block ranking+cap, usage bump. + memory_events audit.
- tests/python/test_memory_prompt.py (PURE, no PG): sanitize neutralizes "ignore previous instructions",
  role hijacks, control chars; length cap; build_memory_block splits categories, caps at 40, never emits
  raw injection. THIS IS THE SECURITY GATE — prove it fails on unsanitized input.
- extend tests/python/test_investigator.py: seed an active memory, run /investigate with FixtureProvider,
  assert the captured system message contains the sanitized operational fact. (investigator must expose
  or the test must inject a way to capture the first system prompt — FixtureProvider already sees messages.)

## Model routing: sonnet-5 (store + service + sanitizer). The sanitizer is security-sensitive → if the
## builder's deny-list looks weak, escalate a review to opus.
