#!/usr/bin/env python3
"""
compare.py: side-by-side comparison of two NOCgentic benchmark result files.

Prints baseline vs candidate for each task: accuracy %, mean/p50/p95 latency,
tokens/sec, plus deltas. Use it to weigh a local open-weight model against the
Gemini cloud baseline.

Usage:
  python bench/compare.py bench/results/<baseline>.json bench/results/<candidate>.json
  python bench/compare.py --baseline A.json --candidate B.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

TASK_ORDER = ["nl_sql", "classify", "summarize"]


def _load(path: str) -> dict[str, Any]:
    with open(path) as f:
        return json.load(f)


def _fmt(v: Any) -> str:
    return "-" if v is None else str(v)


def _delta(cand: Any, base: Any, higher_is_better: bool) -> str:
    if cand is None or base is None:
        return "-"
    d = cand - base
    sign = "+" if d >= 0 else ""
    good = (d >= 0) if higher_is_better else (d <= 0)
    mark = "" if d == 0 else (" win" if good else " REGRESS")
    return f"{sign}{round(d, 1)}{mark}"


def _row(label: str, base: Any, cand: Any, higher_is_better: bool) -> None:
    print(f"  {label:20} baseline={_fmt(base):>10}  candidate={_fmt(cand):>10}  "
          f"delta={_delta(cand, base, higher_is_better):>14}")


def _section(title: str, base: dict[str, Any], cand: dict[str, Any]) -> None:
    print(f"\n[{title}]")
    _row("accuracy %", base.get("accuracy_pct"), cand.get("accuracy_pct"), higher_is_better=True)
    _row("mean latency ms", base.get("mean_latency_ms"), cand.get("mean_latency_ms"), higher_is_better=False)
    _row("p50 latency ms", base.get("p50_latency_ms"), cand.get("p50_latency_ms"), higher_is_better=False)
    _row("p95 latency ms", base.get("p95_latency_ms"), cand.get("p95_latency_ms"), higher_is_better=False)
    _row("tokens/sec", base.get("mean_tokens_per_sec"), cand.get("mean_tokens_per_sec"), higher_is_better=True)
    _row("errors", base.get("errors"), cand.get("errors"), higher_is_better=False)


def main() -> int:
    ap = argparse.ArgumentParser(description="Compare two NOCgentic benchmark result files")
    ap.add_argument("files", nargs="*", help="baseline.json candidate.json (positional)")
    ap.add_argument("--baseline")
    ap.add_argument("--candidate")
    args = ap.parse_args()

    baseline_path = args.baseline
    candidate_path = args.candidate
    if len(args.files) == 2 and not (baseline_path and candidate_path):
        baseline_path, candidate_path = args.files
    if not (baseline_path and candidate_path):
        print("Provide two result files (baseline then candidate).", file=sys.stderr)
        return 2

    base = _load(baseline_path)
    cand = _load(candidate_path)

    bm, cm = base.get("meta", {}), cand.get("meta", {})
    line = "=" * 78
    print(line)
    print(" NOCgentic Benchmark Comparison")
    print(f"   baseline : {bm.get('provider')} / {bm.get('model')}  ({Path(baseline_path).name})")
    print(f"   candidate: {cm.get('provider')} / {cm.get('model')}  ({Path(candidate_path).name})")
    print(line)

    for task in TASK_ORDER:
        _section(task, base.get("per_task", {}).get(task, {}), cand.get("per_task", {}).get(task, {}))
    _section("OVERALL", base.get("overall", {}), cand.get("overall", {}))

    print("\n" + line)
    print(" Note: 'win'/'REGRESS' is from the candidate's perspective. Higher accuracy")
    print(" and tokens/sec are better; lower latency and errors are better.")
    print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
