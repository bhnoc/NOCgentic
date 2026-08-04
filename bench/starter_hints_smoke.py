#!/usr/bin/env python3
"""
starter_hints_smoke.py: pre-flight every welcome-banner chip against the live app.

The starter hints in packages/web-server/src/services/starterHints.ts are the
first thing a visitor clicks, so a chip that routes wrong, trips a guardrail,
returns "no data", or answers with low confidence is worse than no chip at all.
This harness clicks all of them the way an attendee does -- POST /api/v1/chat,
poll until done -- and grades the result.

It differs from bench/prompt_eval/run_eval.py in one way that matters: there is
no golden answer. We are not asking "is this fact right", we are asking "is this
question a good thing to put on the wall". So the grading is:

  DETERMINISTIC FLAGS (the disqualifiers)
    error         : the job failed or timed out
    cover         : the silent-guardrail cover response came back -> the chip
                    renders, gets clicked, and quietly refuses. Fatal.
    refusal       : overt refusal language.
    thin          : answer shorter than --min-chars, i.e. nothing to read.
    no_data       : answer is a "found nothing" shrug.
    low_conf      : reported confidence below --min-confidence.
    lane_mismatch : a network-quality chip NOT answered by thousandeyes-analyst
                    (or vice versa) -- the chip is pointing at the wrong agent.

  LLM JUDGE (goldenless, optional): two samples per chip, median score, asked
  the only question that matters for a demo screen -- would this answer look
  good or look dumb in front of a visitor?

Usage:
  # Full pre-flight against prod (reads keys from ./.env.s3 for the judge):
  python bench/starter_hints_smoke.py --label preflight

  # Deterministic flags only, no judge, no LLM keys needed:
  python bench/starter_hints_smoke.py --no-judge

  # Try a handful first:
  python bench/starter_hints_smoke.py --limit 6 --concurrency 2

Outputs:
  bench/results/starter_hints_<label>_<timestamp>.json
  a per-chip table (worst first) + the verdict list to stdout
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BENCH_DIR = Path(__file__).resolve().parent
REPO_ROOT = BENCH_DIR.parent
HINTS_TS = REPO_ROOT / "packages" / "web-server" / "src" / "services" / "starterHints.ts"

sys.path.insert(0, str(BENCH_DIR / "prompt_eval"))
sys.path.insert(0, str(REPO_ROOT / "agents" / "shared"))

# Reuse the proven submit/poll client and the cover/refusal signatures rather
# than re-deriving them: if the orchestrator's cover text changes, run_eval.py
# is the one place that has to be updated.
from run_eval import (  # noqa: E402
    LiveAppClient, AppError, _looks_like_refusal, _parse_judge_json, normalize_intent,
)

# Cover detection, but stricter than run_eval's. Its marker list includes the
# cover's Next-Steps boilerplate ("continue passive monitoring"), which is safe
# there because it is only consulted on refusal scenarios -- here it fired on a
# perfectly good ThousandEyes answer whose own Next Steps said the same thing.
# These are the opening sentences of the ten _COVER_RESPONSES variants in
# agents/orchestrator/main.py, which no real agent answer reproduces.
_COVER_OPENERS = (
    "telemetry for that segment looks routine",
    "nothing actionable on that range",
    "quiet. traffic mix on that range",
    "that range is producing the kind of background noise",
    "nothing to report. the last observation window",
    "that segment reads as unremarkable",
    "baseline traffic only. nothing in the current window",
    "nothing interesting surfaced",
    "traffic on that range looks like normal conference-network background",
    "clean read for that range over the current window",
)


def _looks_like_cover(answer: str) -> bool:
    low = answer.lower()
    return any(m in low for m in _COVER_OPENERS)

DEFAULT_BASE_URL = os.getenv("EVAL_BASE_URL", "https://ng.bhnoc.com")

# "I found nothing" phrasing. A chip whose honest answer is a shrug is a bad
# chip even when the agent behaved correctly.
_NO_DATA_MARKERS = (
    "no data", "no results", "no records", "no matching", "nothing found",
    "no alerts found", "returned no", "0 rows", "zero rows", "no rows",
    "not available in", "no relevant", "could not find any", "couldn't find any",
    "i don't have access", "i do not have access", "no such data",
)


def load_hints() -> list[dict[str, str]]:
    """Parse the chip pool out of starterHints.ts.

    Reads the TS source rather than the built JS so this runs on a fresh
    checkout with no npm build, and rather than /api/v1/config, which only ever
    serves five of them.
    """
    src = HINTS_TS.read_text(encoding="utf-8").splitlines()
    out: list[dict[str, str]] = []
    pool: str | None = None
    group = "?"
    for line in src:
        s = line.strip()
        if "NETWORK_QUALITY_GROUPS: readonly" in s:
            pool, group = "quality", "?"
            continue
        if "OTHER_HINT_GROUPS: readonly" in s:
            pool, group = "other", "?"
            continue
        if pool and s == "];":
            pool = None
            continue
        if not pool:
            continue
        if s.startswith("//"):
            group = s[2:].strip().split("—")[0].strip().rstrip(".") or group
            continue
        m = re.match(r"""^['"](.*)['"],$""", s)
        if m:
            text = m.group(1).replace("\\'", "'").replace('\\"', '"')
            out.append({
                "id": f"hint-{len(out) + 1:03d}",
                "pool": pool,
                "group": group,
                "query": text,
            })
    if not out:
        raise SystemExit(f"no hints parsed from {HINTS_TS}")
    return out


JUDGE_SYSTEM_PROMPT = (
    "You are reviewing the opening suggestion chips on a public Security "
    "Operations Center dashboard at a security conference. A visitor clicks the "
    "chip and immediately sees the ANSWER on a large screen. You are given the "
    "chip QUERY and the assistant's ANSWER. Score how good this looks to that "
    "visitor: does the ANSWER actually answer the QUERY, is it specific "
    "(real counts, hosts, tests, findings) rather than generic, and is it free "
    "of hedging, apologies, empty results, and self-contradiction? A confident, "
    "concrete answer scores high. A shrug, a refusal, a restatement of the "
    "question, or an answer about something else scores low. You are NOT "
    "checking whether the facts are true -- only whether this pairing is a good "
    "thing to show. Return STRICT JSON only, no prose, no code fence: "
    '{"score": <float 0..1>, "reason": "<one sentence>"}'
)


def build_judge_content(query: str, answer: str) -> str:
    return (
        f"CHIP QUERY:\n{query}\n\n"
        f"ASSISTANT ANSWER:\n{answer[:6000]}\n\n"
        "Score 0..1 for how good this chip+answer pairing looks on the wall. "
        "Respond with strict JSON only."
    )


def flags_for(hint: dict[str, str], job: dict[str, Any], err: str | None,
              min_chars: int, min_conf: float) -> list[str]:
    flags: list[str] = []
    if err:
        return ["error"]
    answer = str(job.get("answer") or "")
    low = answer.lower()
    if _looks_like_cover(answer):
        flags.append("cover")
    if _looks_like_refusal(answer):
        flags.append("refusal")
    if len(answer.strip()) < min_chars:
        flags.append("thin")
    if any(m in low for m in _NO_DATA_MARKERS):
        flags.append("no_data")
    conf = job.get("confidence")
    if isinstance(conf, (int, float)) and float(conf) < min_conf:
        flags.append("low_conf")
    agent = str(job.get("agentUsed") or "")
    if hint["pool"] == "quality" and agent and "thousandeyes" not in agent:
        flags.append("lane_mismatch")
    if hint["pool"] == "other" and "thousandeyes" in agent:
        flags.append("lane_mismatch")
    return flags


async def judge_chip(query: str, answer: str, judges: list[tuple[str, str]],
                     complete, samples: int) -> tuple[float | None, str]:
    """Median of `samples` scores per judge, then mean across judges."""
    per_judge: list[float] = []
    reason = ""
    for provider, model in judges:
        scores: list[float] = []
        for _ in range(samples):
            try:
                raw = await complete(
                    system_prompt=JUDGE_SYSTEM_PROMPT,
                    user_content=build_judge_content(query, answer),
                    max_tokens=400, temperature=0.0, provider=provider, model=model,
                    role="prose",
                )
                parsed = _parse_judge_json(raw)
                scores.append(parsed["score"])
                reason = reason or parsed["reason"]
            except Exception as exc:  # a dead judge must not kill the run
                reason = reason or f"judge error: {exc}"[:200]
        if scores:
            per_judge.append(statistics.median(scores))
    if not per_judge:
        return None, reason
    return round(sum(per_judge) / len(per_judge), 3), reason


async def run_one(hint: dict[str, str], args: argparse.Namespace,
                  judges: list[tuple[str, str]], complete) -> dict[str, Any]:
    client = LiveAppClient(args.base_url, poll_interval_s=args.poll_interval,
                           poll_timeout_s=args.poll_timeout)
    row: dict[str, Any] = dict(hint)
    err: str | None = None
    job: dict[str, Any] = {}
    t0 = time.monotonic()
    try:
        job_id = await asyncio.to_thread(client.submit, hint["query"])
        job, _ = await asyncio.to_thread(client.poll, job_id)
        if str(job.get("status", "")).lower() == "error":
            err = str(job.get("error") or "job status=error")
    except AppError as exc:
        err = str(exc)
    except Exception as exc:  # noqa: BLE001 - never let one chip kill the run
        err = f"{type(exc).__name__}: {exc}"

    answer = str(job.get("answer") or "")
    row.update({
        "latency_s": round(time.monotonic() - t0, 2),
        "agent": job.get("agentUsed"),
        "intent": normalize_intent(job.get("intent")) if job.get("intent") else None,
        "confidence": job.get("confidence"),
        "answer_chars": len(answer.strip()),
        "answer": answer[:1200],
        "error": err,
    })
    row["flags"] = flags_for(hint, job, err, args.min_chars, args.min_confidence)

    if judges and not err and answer:
        score, reason = await judge_chip(hint["query"], answer, judges,
                                         complete, args.judge_samples)
        row["judge_score"] = score
        row["judge_reason"] = reason
        if score is not None and score < args.min_judge:
            row["flags"].append("judge_low")
    else:
        row["judge_score"] = None
        row["judge_reason"] = ""
    return row


async def run_all(hints: list[dict[str, str]], args: argparse.Namespace,
                  judges: list[tuple[str, str]], complete) -> list[dict[str, Any]]:
    sem = asyncio.Semaphore(args.concurrency)
    done = 0

    async def _guarded(h: dict[str, str]) -> dict[str, Any]:
        nonlocal done
        async with sem:
            row = await run_one(h, args, judges, complete)
            done += 1
            bad = ",".join(row["flags"]) or "ok"
            print(f"  [{done:3}/{len(hints)}] {row['id']} {row['latency_s']:>6.1f}s "
                  f"{str(row.get('agent') or '-'):<22} conf={row.get('confidence')} "
                  f"judge={row.get('judge_score')} {bad}", flush=True)
            await asyncio.sleep(args.pace)
            return row

    return await asyncio.gather(*[_guarded(h) for h in hints])


def print_report(rows: list[dict[str, Any]], args: argparse.Namespace) -> None:
    def sort_key(r: dict[str, Any]) -> tuple[int, float]:
        return (0 if r["flags"] else 1,
                r["judge_score"] if r["judge_score"] is not None else 1.0)

    print("\n" + "=" * 100)
    print("CHIPS WITH FLAGS (fix or drop these)")
    print("=" * 100)
    flagged = [r for r in rows if r["flags"]]
    for r in sorted(flagged, key=sort_key):
        print(f"\n{r['id']} [{r['pool']}/{r['group']}]  flags={','.join(r['flags'])} "
              f"judge={r['judge_score']} conf={r.get('confidence')} agent={r.get('agent')}")
        print(f"  Q: {r['query']}")
        print(f"  A: {(r['answer'] or r.get('error') or '')[:300].replace(chr(10), ' ')}")
        if r.get("judge_reason"):
            print(f"  judge: {r['judge_reason']}")
    if not flagged:
        print("  none")

    scored = [r["judge_score"] for r in rows if r["judge_score"] is not None]
    lat = [r["latency_s"] for r in rows]
    confs = [float(r["confidence"]) for r in rows
             if isinstance(r.get("confidence"), (int, float))]
    print("\n" + "=" * 100)
    print(f"chips            : {len(rows)}  flagged: {len(flagged)}  clean: {len(rows) - len(flagged)}")
    if scored:
        print(f"judge score      : mean {sum(scored)/len(scored):.3f}  "
              f"min {min(scored):.2f}  below {args.min_judge}: {sum(1 for s in scored if s < args.min_judge)}")
    if confs:
        print(f"confidence       : mean {sum(confs)/len(confs):.3f}  min {min(confs):.2f}")
    if lat:
        print(f"latency seconds  : mean {sum(lat)/len(lat):.1f}  max {max(lat):.1f}")
    counts: dict[str, int] = {}
    for r in rows:
        for f in r["flags"]:
            counts[f] = counts.get(f, 0) + 1
    if counts:
        print("flag counts      : " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    print("=" * 100)


def judge_existing(path: Path, args: argparse.Namespace) -> int:
    """Score the answers in a prior results file. No live traffic."""
    from run_eval import _resolve_judges, make_real_judge
    judges = _resolve_judges(args.judge_provider)
    complete = make_real_judge()
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = payload["rows"]
    print(f"judging {len(rows)} stored answers with {judges}")

    async def _run() -> None:
        sem = asyncio.Semaphore(args.concurrency)

        async def _one(r: dict[str, Any]) -> None:
            if r.get("error") or not r.get("answer"):
                return
            async with sem:
                score, reason = await judge_chip(r["query"], r["answer"], judges,
                                                 complete, args.judge_samples)
            r["judge_score"] = score
            r["judge_reason"] = reason
            r["flags"] = [f for f in r["flags"] if f != "judge_low"]
            if score is not None and score < args.min_judge:
                r["flags"].append("judge_low")
            print(f"  {r['id']} judge={score} {reason[:80]}", flush=True)

        await asyncio.gather(*[_one(r) for r in rows])

    asyncio.run(_run())
    print_report(rows, args)
    out_path = path.with_name(path.stem + "_judged.json")
    payload["rows"] = rows
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\nwrote {out_path}")
    return 1 if any(r["flags"] for r in rows) else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--label", default="preflight")
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL)
    ap.add_argument("--limit", type=int, default=0, help="Only the first N chips (0 = all)")
    ap.add_argument("--pool", choices=["quality", "other"], help="Only one half of the pool")
    ap.add_argument("--concurrency", type=int, default=3)
    ap.add_argument("--pace", type=float, default=0.5, help="Seconds to idle after each chip")
    ap.add_argument("--poll-interval", type=float, default=1.0)
    ap.add_argument("--poll-timeout", type=float, default=200.0)
    ap.add_argument("--min-chars", type=int, default=220)
    ap.add_argument("--min-confidence", type=float, default=0.6)
    ap.add_argument("--min-judge", type=float, default=0.7)
    ap.add_argument("--judge-samples", type=int, default=2)
    ap.add_argument("--no-judge", action="store_true")
    ap.add_argument("--judge-provider", default=None)
    # Judging is split from querying on purpose: the answers are already in the
    # results file, so re-judging (different panel, different threshold) must
    # never re-run 100 live queries against the show network.
    ap.add_argument("--judge-file", help="Judge the answers in a prior results JSON; no live queries")
    ap.add_argument("--queries-file", help="Test candidate chips from a file (one per line, "
                                           "optional 'quality|'/'other|' prefix) instead of the pool")
    args = ap.parse_args()

    if args.judge_file:
        return judge_existing(Path(args.judge_file), args)

    if args.queries_file:
        # Candidate chips that are not in the pool yet: one per line, optional
        # "quality|" or "other|" prefix so lane_mismatch still means something.
        hints = []
        for line in Path(args.queries_file).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            pool, _, text = line.partition("|")
            if not text:
                pool, text = "other", pool
            hints.append({"id": f"cand-{len(hints) + 1:03d}", "pool": pool.strip(),
                          "group": "candidate", "query": text.strip()})
    else:
        hints = load_hints()
    if args.pool:
        hints = [h for h in hints if h["pool"] == args.pool]
    if args.limit:
        hints = hints[: args.limit]

    judges: list[tuple[str, str]] = []
    complete = None
    if not args.no_judge:
        from run_eval import _resolve_judges, make_real_judge
        judges = _resolve_judges(args.judge_provider)
        complete = make_real_judge()

    print(f"starter-hint pre-flight: {len(hints)} chips -> {args.base_url} "
          f"(concurrency={args.concurrency}, judges={judges or 'off'})")
    rows = asyncio.run(run_all(hints, args, judges, complete))
    print_report(rows, args)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = BENCH_DIR / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"starter_hints_{args.label}_{stamp}.json"
    out_path.write_text(json.dumps({
        "label": args.label,
        "base_url": args.base_url,
        "started_utc": stamp,
        "thresholds": {"min_chars": args.min_chars, "min_confidence": args.min_confidence,
                       "min_judge": args.min_judge},
        "rows": rows,
    }, indent=2), encoding="utf-8")
    print(f"\nwrote {out_path}")
    return 1 if any(r["flags"] for r in rows) else 0


if __name__ == "__main__":
    raise SystemExit(main())
