# ROUTING.md — model routing memory (level9000)

Read before routing a task. One line per task-type: tier that worked (tiers that failed) — date, why.

| task-type | tier | date | note |
|---|---|---|---|
| Pure deterministic Python module + pytest (drain3 template miner) | sonnet-5 (ok) | 2026-07-30 | mechanical-ish but masking-order correctness needed judgment |
| Pluggable embeddings seam + stub (768-dim, L2-norm) | sonnet-5 (ok) | 2026-07-30 | small; lazy-import design got right first try |
| Postgres+pgvector store + migration + tests | sonnet-5 (ok) | 2026-07-30 | got `%s::vector` cast right in report but shipped code w/o it on one path — clean-state run caught it |
| FastAPI integrator + agentic loop + AnomalySource seam | sonnet-5 (ok) | 2026-07-30 | in-process tests passed but missed container path bug — clean-state caught it |
| Repo-wide exploration / architecture mapping | Explore/haiku-ish (ok) | 2026-07-30 | 4 explorers mapped 3 codebases well |

## Lessons
- sonnet-5 is the right default for all build tasks this slice; none needed opus. No cascades.
- **Sub-agent "tests pass" is NOT done.** Two real bugs (`::vector` cast, migration path) passed the
  builders' own runs and only failed on clean-state / container verification. Always verify from cold.
- Builders' self-reported code can drift from what's on disk (store agent claimed casts it didn't ship).
  Trust the clean run, not the report.
