# Prompt Eval + Optimization (NOCgentic): plan

Goal: the current Gemini system/user prompts are "good but unproven" (one show). For the
larger next show, systematically test + evolve prompt VERSIONS that improve: (1) returns
what the user wants, (2) accuracy, (3) speed. Reported as 3 SEPARATE channels (no composite).

Use cases (what attendees actually do):
- Look at their OWN data by IP or MAC, then dive in.
- Threat-hunting angle.
- Alert-validation angle.

Decisions (locked with James 2026-07-25):
- Extend NOCgentic's bench/ harness (reuse real llm_complete + RealBits), not skillz_eval port.
- Golden scenarios authored from REAL seeded Athena data (ground truth verified by querying Athena).
- 3 channels reported separately: accuracy-vs-golden | "answered what was asked" (LLM judge panel) | speed.

Prompts under optimization (7):
- orchestrator: CLASSIFY_SYSTEM_PROMPT, HINTS_SYSTEM_PROMPT
- athena-hunter: SQL_GEN_PROMPT, SYSTEM_PROMPT (answer synthesis)  <- core of by-IP/dive-in
- alert-triage: QUERY_PARSE_PROMPT, SYSTEM_PROMPT  <- alert validation
- thousandeyes: SYSTEM_PROMPT

Design:
- bench/scenarios/data-facts.json  : real verifiable facts from Athena (recon agent)
- bench/scenarios/golden.jsonl      : authored scenarios {id, use_case, query, golden_answer, must_include, must_not_include, expected_intent}
- bench/prompt_eval/variants/       : prompt-variant files (v1=current baseline, v2..N candidates)
- bench/prompt_eval/run_eval.py     : fix model=gemini, run scenarios under a chosen variant set, score 3 channels
- judge panel: cross-checked LLM judges score "did it answer what was asked" + faithfulness; never self-grade if avoidable
- output: per-variant scorecard, compare variants, pick winners per prompt

Lessons to apply from skillz_eval FINDINGS:
- Gemini can loop/non-converge on multi-step hunts (windows-admin-shares 0/15) -> prompt should push convergence.
- Report channels separately, flag low-N, contamination-aware (don't leak golden answers into prompts).
- Gemini is cheap + near-parity accuracy; enumeration/volume hunts are its strength, sequence/coercion its relative weakness.
