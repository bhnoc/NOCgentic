# NOCgentic END-TO-END Prompt Eval Harness

Measures whether the current Gemini prompts return what an attendee actually
wants: accurately, and fast. It does this by driving the REAL live app end to
end (the exact attendee path), not by testing prompts in isolation. Each
scenario is submitted to the app, polled to completion, and scored on THREE
SEPARATE channels. This is also the tool for A/B testing prompt variants later.

## What it does

For each scenario in `bench/scenarios/golden.jsonl`:

1. `POST <base-url>/api/v1/chat` with `{"query": "<scenario query>"}` -> `{jobId}`.
2. Poll `GET <base-url>/api/v1/chat/<jobId>` until `status` is `done` or `error`.
3. Score the returned `answer` / `agentUsed` / `confidence` on 3 channels.

Every scenario uses its OWN cookie jar (one client per scenario). This matters:
the IDOR fix binds a job to the `bh_sid` cookie the app sets on the first
response, so submit and poll must share cookies or the poll gets a 404. The
harness reuses one cookie jar per scenario automatically.

The app's `answer` markdown contains literal newlines, so every response body is
parsed with `json.loads(..., strict=False)`.

## The 3 scoring channels (reported SEPARATELY, no composite)

### 1. Accuracy (deterministic, 0..1)

Mean of three components, all kept in the result detail dict:

- **routing**: did `agentUsed` match `expected_intent`? `threat_hunter` maps to
  `athena_hunter`. For guardrail scenarios (`expected_intent: refused`),
  `agentUsed` is unreliable (may be `error`, `refused`, or absent), so routing
  is judged by whether the ANSWER refuses rather than answers.
- **must_include**: fraction of `must_include` strings present in the answer
  (case-insensitive).
- **must_not_include**: 0 if ANY forbidden string is present (hard fail on a
  leaked prompt or a wrong "benign" verdict), else 1.

### 2. Relevance / "answered what was asked" (LLM judge panel, 0..1)

The scenario query, the golden answer, and the model's answer are sent to a
JUDGE PANEL (2-3 judges, averaged, to reduce single-judge noise). Each judge
scores whether the answer actually addresses the question and stays faithful to
the golden (no fabricated specifics). Judges return strict JSON
`{"score": 0..1, "reason": "..."}`.

Judge selection (auto, or forced with `--judge-provider`):
- If `OPENROUTER_API_KEY` is set: two Claude judges (sonnet + haiku) on
  OpenRouter. This judges with a DIFFERENT model than the Gemini under test.
- Else if `GEMINI_API_KEY` is set: a single Gemini judge (self-family, flagged
  by `relevance_n=1` in the output).

Robustness: if a judge errors, it is dropped and the rest are averaged. If ALL
judges fail, relevance is marked **unavailable** (`null`), NOT 0. Faithfulness
is folded into the judge (no fabricated specifics) plus the deterministic
`must_not_include` hard checks.

### 3. Speed

Wall-clock latency per scenario (submit -> done), plus the model's self-reported
`confidence`. Aggregated as mean / p50 / p95.

## Running the baseline (real, against the live app)

The machine running this must be allow-listed to the box. The harness verifies
`/health` returns 200 before doing anything.

```bash
# From a repo checkout (recommended, see the results warning below):
pip install -r agents/shared/requirements.txt -r bench/prompt_eval/requirements.txt

# Judge with Claude on OpenRouter (different model than the Gemini under test):
export OPENROUTER_API_KEY=...     # optional but preferred
# else the judge falls back to a single Gemini judge:
export GEMINI_API_KEY=...

python bench/prompt_eval/run_eval.py --label v1-baseline
```

Useful flags:

```
--label v1-baseline          # goes in the results filename
--base-url https://nocgentic.bhnoc.com   # default; override for staging
--scenarios path/to/golden.jsonl    # default bench/scenarios/golden.jsonl
--judge-provider openrouter  # force judge provider (openrouter|gemini|local)
--poll-interval 1.0          # seconds between polls
--poll-timeout 200           # max seconds to wait per scenario
```

Output: a per-scenario table, a per-use-case breakdown, an overall 3-channel
summary to stdout, and a machine-readable
`bench/prompt_eval/results/<label>_<timestamp>.json`.

## Offline dry run (no network, no keys)

```bash
python bench/prompt_eval/run_eval.py --dry-run --label smoke
python bench/prompt_eval/run_eval.py --dry-run --dry-mode bad --label smoke-bad
```

`--dry-run` stubs the HTTP client and the judge so the full pipeline (submit,
poll, 3-channel scoring, aggregation, results file) runs on a bare interpreter.
`--dry-mode good` produces passing answers; `--dry-mode bad` produces wrong
routing, missing `must_include`, and a leaked `must_not_include` token so you can
confirm the hard-fail path scores low without crashing.

## Results directory warning

Results default to `bench/prompt_eval/results/`. On the deploy box that path is
under `/opt/nocgentic/app`, which the deploy rsync wipes with `--delete`, so results
are erased on the next deploy. To keep them:

- Run from a repo checkout (not the deployed tree), or
- Copy the JSON off the box after a run, or
- Set `BENCH_RESULTS_DIR=/home/ubuntu/eval-results` to a deploy-safe path.

## Testing prompt variants (A/B)

`variants/` holds prompt-override sets: `v1` is the current baseline (the prompts
live in `agents/*/main.py`), `v2..N` are candidates. Because this harness drives
the LIVE app end to end, a variant is only exercised once its prompts are running
on the box. So the variant flow is:

1. Author the variant as a set of prompt overrides under
   `bench/prompt_eval/variants/<name>/` (one file per changed prompt, e.g.
   `athena-hunter.SYSTEM_PROMPT`, `orchestrator.CLASSIFY_SYSTEM_PROMPT`).
2. Apply the overrides to the agent source and DEPLOY that variant to the box
   (or to a staging deployment).
3. Run the harness against it with a matching label:
   `python bench/prompt_eval/run_eval.py --label v2-convergence`.
4. Compare the `results/<label>_*.json` files across variants, per channel and
   per use-case. Pick winners per prompt.

Note: `bench/prompt_eval/variants/` does not exist yet. Create it when the first
candidate variant is authored. Do NOT commit or deploy from this harness itself.
