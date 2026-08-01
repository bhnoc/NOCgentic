#!/usr/bin/env python3
"""
run_bench.py: NOCgentic model benchmark harness.

Compares LLM providers/models (gemini | openrouter | local) on the three REAL
agent tasks, measuring speed (latency, tokens/sec) and accuracy (per-task rubric).

It calls the REAL `llm_complete` from agents/shared/llm_client.py with the REAL
system prompts imported straight out of the agent modules, so it exercises the
exact code path the app uses. Provider selection is by env alone (LLM_PROVIDER,
GEMINI_API_KEY, LOCAL_LLM_BASE_URL, LOCAL_LLM_MODEL, ...), same as the agents.

Tasks:
  1. nl_sql    : athena-hunter SQL_GEN_PROMPT. Score: parses as a single SELECT,
                  hits the expected table, has a dt partition filter and a LIMIT.
  2. classify  : orchestrator CLASSIFY_SYSTEM_PROMPT. Score: valid JSON with an
                  "intent" field that matches the expected route.
  3. summarize : alert-triage SYSTEM_PROMPT over a canned triage-data blob.
                  Score: cites the real numbers, invents no numbers, emits a
                  parseable ```json {"confidence": ...}``` fence.

Usage:
  # Gemini baseline (cloud):
  LLM_PROVIDER=gemini GEMINI_API_KEY=... python bench/run_bench.py

  # Local open-weight model (llama.cpp / Ollama / vLLM on the GPU box):
  LLM_PROVIDER=local LOCAL_LLM_BASE_URL=http://localhost:8080/v1 \
      LOCAL_LLM_MODEL=qwen2.5-7b-instruct python bench/run_bench.py

  # Dry run: no network, no deps, stubbed llm_complete: proves scoring/timing/output:
  python bench/run_bench.py --dry-run

Outputs:
  bench/results/<provider>_<model>_<timestamp>.json   (machine-readable)
  a human-readable summary table to stdout
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
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Paths + import bootstrap
# ---------------------------------------------------------------------------

BENCH_DIR = Path(__file__).resolve().parent
REPO_ROOT = BENCH_DIR.parent
AGENTS_DIR = REPO_ROOT / "agents"
SHARED_DIR = AGENTS_DIR / "shared"
# Default results dir is bench/results, BUT on the deploy box that path is inside
# /opt/nocgentic/app which deploy.sh rsyncs with --delete, so results get wiped on the
# next deploy. Set BENCH_RESULTS_DIR to a deploy-safe path (e.g. /home/ubuntu/bench-results)
# to keep raw result JSON across deploys.
import os as _os
RESULTS_DIR = Path(_os.getenv("BENCH_RESULTS_DIR") or (BENCH_DIR / "results"))

# The agent main.py modules compute _SHARED as parents[2]/"shared", which is
# correct only inside a container layout. To import the REAL prompts + REAL
# llm_complete here we put the real agents/shared on sys.path ourselves, plus
# each agent dir (so `import main` resolves per agent).
for p in (str(SHARED_DIR), str(AGENTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

# OTEL must be stubbed off so importing telemetry/llm_client never phones home.
os.environ.setdefault("OTEL_ENABLED", "false")
os.environ.setdefault("TRACE_S3_ENABLED", "false")
os.environ.setdefault("LANGSMITH_TRACING", "false")
os.environ.setdefault("LANGCHAIN_TRACING_V2", "false")


TASK_ORDER = ["nl_sql", "classify", "summarize"]


# ---------------------------------------------------------------------------
# Dry-run stubs: inject minimal fake modules for the agent import-time deps
# that are not installed (fastapi, pydantic, httpx). This lets --dry-run import
# the REAL prompts and REAL parser helpers without the full agent venv. We do
# NOT stub langchain: real runs need it, and dry-run replaces llm_complete.
# ---------------------------------------------------------------------------

def _install_import_stubs() -> None:
    import types

    def _ensure(name: str) -> types.ModuleType:
        if name in sys.modules:
            return sys.modules[name]
        mod = types.ModuleType(name)
        sys.modules[name] = mod
        return mod

    # ---- pydantic (BaseModel + Field) ----
    try:
        import pydantic  # noqa: F401
    except Exception:
        pyd = _ensure("pydantic")

        class _BaseModel:
            def __init__(self, **kw: Any) -> None:
                for k, v in kw.items():
                    setattr(self, k, v)

            def __init_subclass__(cls, **kw: Any) -> None:
                super().__init_subclass__(**kw)

        def _Field(default: Any = None, **kw: Any) -> Any:
            if "default_factory" in kw and kw["default_factory"] is not None:
                try:
                    return kw["default_factory"]()
                except Exception:
                    return default
            return default

        def _validator(*a: Any, **k: Any):
            def _wrap(fn):
                return fn
            return _wrap

        pyd.BaseModel = _BaseModel
        pyd.Field = _Field
        pyd.validator = _validator
        pyd.field_validator = _validator

    # ---- fastapi (FastAPI, HTTPException, Header) ----
    try:
        import fastapi  # noqa: F401
    except Exception:
        fa = _ensure("fastapi")

        class _App:
            def __init__(self, *a: Any, **k: Any) -> None:
                pass

            def _route(self, *a: Any, **k: Any):
                def _wrap(fn):
                    return fn
                return _wrap

            get = post = patch = put = delete = _route

        class _HTTPException(Exception):
            def __init__(self, status_code: int = 500, detail: str = "") -> None:
                self.status_code = status_code
                self.detail = detail

        def _Header(default: Any = None, **k: Any) -> Any:
            return default

        fa.FastAPI = _App
        fa.HTTPException = _HTTPException
        fa.Header = _Header

    # ---- httpx (only referenced at import for type/except; stub the surface) ----
    try:
        import httpx  # noqa: F401
    except Exception:
        hx = _ensure("httpx")

        class _Err(Exception):
            pass

        class _AsyncClient:
            def __init__(self, *a: Any, **k: Any) -> None:
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a: Any):
                return False

            async def post(self, *a: Any, **k: Any):
                raise _Err("dry-run: no network")

        hx.AsyncClient = _AsyncClient
        hx.ConnectError = type("ConnectError", (_Err,), {})
        hx.TimeoutException = type("TimeoutException", (_Err,), {})
        hx.HTTPStatusError = type("HTTPStatusError", (_Err,), {})

    # ---- boto3 (athena_client imports it at module load) ----
    try:
        import boto3  # noqa: F401
    except Exception:
        b = _ensure("boto3")

        class _Session:
            def __init__(self, *a: Any, **k: Any) -> None:
                pass

            def client(self, *a: Any, **k: Any):
                raise RuntimeError("dry-run: no AWS")

        def _client(*a: Any, **k: Any):
            raise RuntimeError("dry-run: no AWS")

        b.Session = _Session
        b.client = _client


# ---------------------------------------------------------------------------
# Import the REAL prompts, REAL parsers, and REAL llm_complete.
# ---------------------------------------------------------------------------

def _load_agent_module(agent_dirname: str, attr_names: list[str]) -> Any:
    """Import an agent's main.py by temporarily making its dir the priority path.

    Each agent has its own `main.py`; we import them one at a time under a unique
    module alias so they don't collide in sys.modules.
    """
    import importlib.util

    main_path = AGENTS_DIR / agent_dirname / "main.py"
    alias = f"bench_agent_{agent_dirname.replace('-', '_')}"
    if alias in sys.modules:
        return sys.modules[alias]

    # Ensure the agent's own dir is importable (defensive; prompts live in main).
    agent_dir = str(AGENTS_DIR / agent_dirname)
    if agent_dir not in sys.path:
        sys.path.insert(0, agent_dir)

    spec = importlib.util.spec_from_file_location(alias, main_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot build import spec for {main_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    spec.loader.exec_module(module)
    for a in attr_names:
        if not hasattr(module, a):
            raise ImportError(f"{agent_dirname}/main.py missing expected attr {a!r}")
    return module


class RealBits:
    """Holds the real prompts / parsers / llm_complete pulled from the app."""

    def __init__(self) -> None:
        athena = _load_agent_module("athena-hunter", ["SQL_GEN_PROMPT", "_parse_sql_response"])
        orch = _load_agent_module("orchestrator", ["CLASSIFY_SYSTEM_PROMPT", "extract_json", "VALID_INTENTS"])
        triage = _load_agent_module("alert-triage", ["SYSTEM_PROMPT"])

        self.SQL_GEN_PROMPT: str = athena.SQL_GEN_PROMPT
        self.parse_sql_response: Callable[[str], list[str]] = athena._parse_sql_response

        self.CLASSIFY_SYSTEM_PROMPT: str = orch.CLASSIFY_SYSTEM_PROMPT
        self.extract_json: Callable[[str], Any] = orch.extract_json
        self.VALID_INTENTS: set[str] = set(orch.VALID_INTENTS)

        self.TRIAGE_SYSTEM_PROMPT: str = triage.SYSTEM_PROMPT

        from llm_client import llm_complete, get_last_llm_metrics  # noqa: E402
        self.llm_complete = llm_complete
        self.get_last_llm_metrics = get_last_llm_metrics


# ---------------------------------------------------------------------------
# User-content builders: mirror how each agent frames the call.
# ---------------------------------------------------------------------------

def build_sql_user_content(query: str, iocs: list[str], today: str) -> str:
    """Mirror athena-hunter.generate_sql user_content (dates + IOC context)."""
    from datetime import datetime as _dt, timedelta as _td
    _today = _dt.strptime(today, "%Y-%m-%d")
    _yesterday = (_today - _td(days=1)).strftime("%Y-%m-%d")
    _week_ago = (_today - _td(days=7)).strftime("%Y-%m-%d")
    _month_ago = (_today - _td(days=30)).strftime("%Y-%m-%d")

    ioc_ctx = ""
    ips = [i for i in iocs if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", i)]
    uids = [i for i in iocs if re.fullmatch(r"[A-Za-z][A-Za-z0-9]{15,25}", i)]
    if ips:
        ioc_ctx += f"IPs to investigate: {', '.join(ips[:5])}\n"
    if uids:
        ioc_ctx += f"UIDs: {', '.join(uids[:3])}\n"

    return (
        f"Partition dates you may use:\n"
        f"- today: {today}\n"
        f"- yesterday: {_yesterday}\n"
        f"- 7 days ago: {_week_ago}\n"
        f"- 30 days ago: {_month_ago}\n\n"
        f"Analyst query: {query}\n\n"
        f"{ioc_ctx}"
        "Build the date filter based on the analyst's time scope. "
        "For single-day queries use `dt = 'today'`. For multi-day ranges use "
        "`dt >= 'START' AND dt <= 'today'`."
    )


def build_summarize_user_content(triage_data: dict[str, Any]) -> tuple[str, str]:
    """Mirror alert-triage.llm_triage user_content. Returns (query, user_content)."""
    query = str(triage_data.get("analyst_focus", "Summarize the current posture"))
    data_str = json.dumps(triage_data, default=str)[:10000]
    user_content = (
        f"**Analyst Request:** {query}\n\n"
        f"**Triage Data (untrusted):**\n"
        f"<<<UNTRUSTED_TELEMETRY\n```json\n{data_str}\n```\n>>>"
    )
    return query, user_content


# ---------------------------------------------------------------------------
# Scorers: return (score_float_0_1, detail_dict)
# ---------------------------------------------------------------------------

# Every real Corelight/Zeek table the SQL_GEN_PROMPT advertises.
_KNOWN_TABLES = {
    "conn", "dns", "http", "ssl", "ssh", "files", "notice", "weird",
    "suricata_corelight", "alerts", "uid_lookup", "fuid_lookup",
}


def _try_sqlparse_single_select(sql: str) -> tuple[bool, bool]:
    """Return (parsed_ok, is_single_select). Uses sqlparse if available, else regex."""
    try:
        import sqlparse
        statements = [s for s in sqlparse.parse(sql) if str(s).strip()]
        if len(statements) != 1:
            return True, False
        stmt = statements[0]
        stmt_type = stmt.get_type()  # 'SELECT', 'INSERT', 'UNKNOWN', ...
        return True, stmt_type == "SELECT"
    except ImportError:
        pass
    # Regex fallback: one statement, starts with SELECT, no stacked ';' + more SQL.
    body = sql.strip().rstrip(";").strip()
    if ";" in body:
        return True, False
    is_select = bool(re.match(r"(?is)^\s*(with\b.*?\bselect\b|select\b)", body))
    return True, is_select


def _tables_referenced(sql: str) -> set[str]:
    """Crude table extraction: names after FROM / JOIN."""
    found = set()
    for m in re.finditer(r"(?is)\b(?:from|join)\s+([a-zA-Z_][a-zA-Z0-9_]*)", sql):
        found.add(m.group(1).lower())
    return found


def score_nl_sql(raw: str, case: dict[str, Any], real: RealBits) -> tuple[float, dict[str, Any]]:
    """Structural SQL score. Four equal checks, averaged, gated on parse+select.

    Checks:
      1. parses + is a single SELECT (gate: 0 if it isn't well-formed at all)
      2. references at least one expected/known table (right table for the question)
      3. has a dt partition filter
      4. has a LIMIT
    """
    detail: dict[str, Any] = {"case": case["id"]}
    queries = real.parse_sql_response(raw)
    detail["parsed_query_count"] = len(queries)
    if not queries:
        detail["reason"] = "no SELECT parsed from model output"
        return 0.0, detail

    # Score the best of the (up to 3) queries the model produced.
    best = 0.0
    best_detail: dict[str, Any] = {}
    expected = {t.lower() for t in case.get("expected_tables", [])}
    for sql in queries[:3]:
        parsed_ok, is_select = _try_sqlparse_single_select(sql)
        if not (parsed_ok and is_select):
            cand = {"well_formed_select": False}
            if 0.0 >= best:
                best_detail = cand
            continue
        tables = _tables_referenced(sql)
        hits_expected = bool(tables & expected) if expected else bool(tables & _KNOWN_TABLES)
        has_dt = bool(re.search(r"(?i)\bdt\b", sql))
        has_limit = bool(re.search(r"(?i)\blimit\s+\d+", sql))
        checks = {
            "well_formed_select": True,
            "hits_expected_table": hits_expected,
            "has_dt_filter": has_dt,
            "has_limit": has_limit,
        }
        s = sum(1 for v in checks.values() if v) / 4.0
        if s > best:
            best = s
            best_detail = {**checks, "tables": sorted(tables)}

    detail.update(best_detail)
    detail["expected_tables"] = sorted(expected)
    return best, detail


def score_classify(raw: str, case: dict[str, Any], real: RealBits) -> tuple[float, dict[str, Any]]:
    """Valid JSON with intent field (0.5) + intent matches expected route (0.5)."""
    detail: dict[str, Any] = {"case": case["id"], "expected_intent": case["expected_intent"]}
    try:
        parsed = real.extract_json(raw)
    except Exception as exc:
        detail["reason"] = f"JSON not parseable: {exc}"
        return 0.0, detail
    if not isinstance(parsed, dict) or "intent" not in parsed:
        detail["reason"] = "parsed but no 'intent' field"
        return 0.0, detail

    intent = parsed.get("intent")
    if intent == "threat_hunter":  # legacy alias the orchestrator remaps
        intent = "athena_hunter"
    detail["got_intent"] = intent
    detail["valid_json_with_intent"] = True
    matched = intent == case["expected_intent"]
    detail["intent_matched"] = matched
    return (1.0 if matched else 0.5), detail


_NUM_RE = re.compile(r"\d[\d,]*")


def _numbers_in(text: str) -> set[str]:
    return {m.group(0).replace(",", "") for m in _NUM_RE.finditer(text)}


# Numbers the model is allowed to emit even if not in the input: the confidence
# fence (0.xx), section header ordinals in "## Next Steps" lists, and years.
_ALLOWED_STRAY = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "2026", "10", "24"}


def score_summarize(raw: str, case: dict[str, Any], real: RealBits) -> tuple[float, dict[str, Any]]:
    """Faithful summary score. Three checks, averaged:
      1. cites the required numbers from the input (counts/severities)
      2. no hallucinated numbers (every big number in the summary traces to input)
      3. a parseable ```json {"confidence": ...}``` fence is present
    Empty-data cases additionally expect a low confidence (< 0.3).
    """
    detail: dict[str, Any] = {"case": case["id"]}
    triage_data = case["triage_data"]
    must_cite = [str(n) for n in case.get("must_cite_numbers", [])]

    # Strip the confidence fence before counting numbers: its value (e.g. 0.82)
    # would otherwise tokenize into a stray "82" and read as a hallucinated count.
    raw_no_fence = re.sub(
        r'```json\s*\{[^}]*"confidence"[^}]*\}\s*```', "", raw
    )
    answer_nums = _numbers_in(raw_no_fence)

    # Check 1: required numbers cited.
    cited = [n for n in must_cite if n in answer_nums]
    cite_score = (len(cited) / len(must_cite)) if must_cite else 1.0
    detail["cited_numbers"] = cited
    detail["missing_numbers"] = [n for n in must_cite if n not in answer_nums]

    # Check 2: no hallucinated numbers. Build the set of numbers legitimately in
    # the input blob, then flag any 2+ digit number in the summary not traceable.
    input_nums = _numbers_in(json.dumps(triage_data, default=str))
    allowed = input_nums | _ALLOWED_STRAY
    hallucinated = [
        n for n in answer_nums
        if n not in allowed and len(n) >= 2
    ]
    no_hallucination = len(hallucinated) == 0
    detail["hallucinated_numbers"] = hallucinated

    # Check 3: confidence fence present + parseable.
    conf = None
    m = re.search(r'```json\s*\{[^}]*"confidence"\s*:\s*([0-9.]+)[^}]*\}\s*```', raw)
    if m:
        try:
            conf = float(m.group(1))
        except ValueError:
            conf = None
    fence_ok = conf is not None
    detail["confidence"] = conf
    detail["confidence_fence_ok"] = fence_ok

    score = (cite_score + (1.0 if no_hallucination else 0.0) + (1.0 if fence_ok else 0.0)) / 3.0

    # Empty-data cases: the prompt asks for confidence < 0.3. Penalize a
    # confidently-wrong summary of nothing.
    if case.get("expect_low_confidence"):
        low_ok = conf is not None and conf < 0.3
        detail["low_confidence_expected"] = True
        detail["low_confidence_ok"] = low_ok
        # Fold as a 4th check.
        score = (score * 3.0 + (1.0 if low_ok else 0.0)) / 4.0

    return score, detail


# ---------------------------------------------------------------------------
# Per-task runners: build the call, invoke llm_complete with the REAL params.
# ---------------------------------------------------------------------------

async def run_nl_sql_case(real: RealBits, case: dict[str, Any], today: str, complete) -> dict[str, Any]:
    user_content = build_sql_user_content(case["query"], case.get("iocs", []), today)
    raw = await complete(
        system_prompt=real.SQL_GEN_PROMPT,
        user_content=user_content,
        max_tokens=4096,
        temperature=0.0,
        thinking_budget=512,
    )
    score, detail = score_nl_sql(raw, case, real)
    return {"raw": raw, "score": score, "detail": detail}


async def run_classify_case(real: RealBits, case: dict[str, Any], complete) -> dict[str, Any]:
    # Must mirror the orchestrator's real llm_classify params (max_tokens=1024,
    # thinking_budget=512) so the benchmark tests the production call. The old
    # 256/0 combo truncated the JSON on flash-lite (thinking ate the budget).
    raw = await complete(
        system_prompt=real.CLASSIFY_SYSTEM_PROMPT,
        user_content=case["query"],
        max_tokens=1024,
        temperature=0.0,
        thinking_budget=512,
    )
    score, detail = score_classify(raw, case, real)
    return {"raw": raw, "score": score, "detail": detail}


async def run_summarize_case(real: RealBits, case: dict[str, Any], complete) -> dict[str, Any]:
    _query, user_content = build_summarize_user_content(case["triage_data"])
    raw = await complete(
        system_prompt=real.TRIAGE_SYSTEM_PROMPT,
        user_content=user_content,
        max_tokens=4096,
        temperature=0.1,
        thinking_budget=0,
    )
    score, detail = score_summarize(raw, case, real)
    return {"raw": raw, "score": score, "detail": detail}


# ---------------------------------------------------------------------------
# Metrics helpers
# ---------------------------------------------------------------------------

def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * p
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    frac = k - lo
    return s[lo] + (s[hi] - s[lo]) * frac


def summarize_task(rows: list[dict[str, Any]]) -> dict[str, Any]:
    ok = [r for r in rows if not r.get("error")]
    lats = [r["latency_ms"] for r in ok if r.get("latency_ms") is not None]
    tps = [r["tokens_per_sec"] for r in ok if r.get("tokens_per_sec")]
    scores = [r["score"] for r in rows]  # errored cases score 0, count against accuracy
    return {
        "cases": len(rows),
        "errors": sum(1 for r in rows if r.get("error")),
        "accuracy_pct": round(100.0 * (sum(scores) / len(scores)) if scores else 0.0, 1),
        "mean_latency_ms": round(statistics.mean(lats), 1) if lats else None,
        "p50_latency_ms": round(_pct(lats, 0.50), 1) if lats else None,
        "p95_latency_ms": round(_pct(lats, 0.95), 1) if lats else None,
        "mean_tokens_per_sec": round(statistics.mean(tps), 1) if tps else None,
        "total_output_tokens": sum(r.get("output_tokens") or 0 for r in ok),
    }


# ---------------------------------------------------------------------------
# Dry-run stub llm_complete
# ---------------------------------------------------------------------------

def make_stub_complete(mode: str = "good"):
    """Return an async llm_complete stub that emits canned good/bad output per task.

    Detects the task from the system prompt content. Also records fake metrics so
    the timing/token plumbing is exercised. mode 'good' -> high scores, 'bad' ->
    junk that must score low without crashing the harness.
    """
    call_state = {"n": 0}

    async def _stub(system_prompt: str, user_content: str, **kwargs: Any) -> str:
        await asyncio.sleep(0.005)  # simulate a little wall-clock latency
        call_state["n"] += 1
        sp = system_prompt

        is_sql = "SQL query generator" in sp
        is_classify = "routing brain" in sp
        is_summary = "SOC triage specialist" in sp

        if mode == "bad":
            # Junk that the scorers must survive and mark down.
            if is_classify:
                return "sorry, I cannot classify that as JSON"
            if is_sql:
                return "DROP TABLE conn; that is not a select"
            return "The network looks fine, roughly 9999 events happened."

        # mode == "good": produce plausible correct-ish outputs.
        if is_sql:
            # Pick a table hinted by the user content.
            table = "alerts"
            for t in ("conn", "dns", "ssl", "http", "files", "uid_lookup", "suricata_corelight", "alerts"):
                if t.replace("_", " ") in user_content.lower() or t in user_content.lower():
                    table = t
                    break
            if "top talker" in user_content.lower():
                table = "conn"
            if "uid" in user_content.lower():
                table = "uid_lookup"
            return json.dumps([
                f"SELECT * FROM {table} WHERE dt = '2026-07-22' LIMIT 100"
            ])
        if is_classify:
            q = user_content.lower()
            if "poem" in q or "ignore previous" in q or "system prompt" in q:
                intent = "refused"
            elif "packet loss" in q or "latency" in q or "bgp" in q:
                intent = "thousandeyes_analyst"
            elif "alert" in q or "severity" in q or "ids" in q or "fired" in q:
                intent = "alert_triage"
            else:
                intent = "athena_hunter"
            return json.dumps({"intent": intent, "confidence": 0.9, "reasoning": "stub"})
        if is_summary:
            # Echo the real numbers from the blob so the faithfulness checks pass.
            m = re.search(r"UNTRUSTED_TELEMETRY\s*```json\s*(\{.*?\})\s*```", user_content, re.DOTALL)
            data = {}
            if m:
                try:
                    data = json.loads(m.group(1))
                except Exception:
                    data = {}
            ta = data.get("total_alerts", 0)
            tf = data.get("total_flows", 0)
            td = data.get("total_dns", 0)
            sb = data.get("severity_breakdown", {})
            empty = (ta in (0, "0")) and (tf in (0, "0"))
            conf = 0.2 if empty else 0.82
            crit = sb.get("critical", 0)
            high = sb.get("high", 0)
            return (
                f"## Answer\n"
                f"Observed {ta} alerts across {tf} flows and {td} DNS records.\n\n"
                f"## Key Entities\n"
                f"- {crit} critical, {high} high severity signatures.\n\n"
                f"## Risk\n"
                f"Scoped to the observation window.\n\n"
                f"## Next Steps\n"
                f"1. Continue monitoring.\n\n"
                f"```json\n{{\"confidence\": {conf}}}\n```"
            )
        return "unrecognized task"

    return _stub


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def run_all(real: RealBits, cases: dict[str, Any], complete, today: str) -> dict[str, list]:
    results: dict[str, list] = {t: [] for t in TASK_ORDER}

    runners = {
        "nl_sql": lambda c: run_nl_sql_case(real, c, today, complete),
        "classify": lambda c: run_classify_case(real, c, complete),
        "summarize": lambda c: run_summarize_case(real, c, complete),
    }

    for task in TASK_ORDER:
        for case in cases.get(task, []):
            row: dict[str, Any] = {"id": case["id"], "task": task}
            t0 = time.monotonic()
            try:
                out = await runners[task](case)
                row["latency_ms"] = round((time.monotonic() - t0) * 1000, 1)
                row["score"] = out["score"]
                row["detail"] = out["detail"]
                row["output_preview"] = out["raw"][:400]
                # Pull real token metrics from the last llm_complete call.
                try:
                    lm = real.get_last_llm_metrics()
                except Exception:
                    lm = {}
                row["output_tokens"] = lm.get("output_tokens")
                row["input_tokens"] = lm.get("input_tokens")
                row["tokens_per_sec"] = lm.get("tok_per_sec")
                row["provider_latency_ms"] = lm.get("latency_ms")
            except Exception as exc:  # a junk model must not crash the harness
                row["latency_ms"] = round((time.monotonic() - t0) * 1000, 1)
                row["score"] = 0.0
                row["error"] = f"{type(exc).__name__}: {exc}"
                row["detail"] = {"case": case["id"], "reason": "exception during call/scoring"}
            print(f"  [{task:9}] {case['id']:22} score={row['score']:.2f} "
                  f"lat={row['latency_ms']}ms" + (f" ERR={row['error']}" if row.get("error") else ""))
            results[task].append(row)

    return results


def print_summary_table(provider: str, model: str, per_task: dict[str, Any], overall: dict[str, Any]) -> None:
    line = "=" * 78
    print("\n" + line)
    print(f" NOCgentic Model Benchmark: provider={provider} model={model}")
    print(line)
    hdr = f"{'task':11} {'acc%':>6} {'mean ms':>9} {'p50 ms':>8} {'p95 ms':>8} {'tok/s':>7} {'err':>4}"
    print(hdr)
    print("-" * 78)
    for task in TASK_ORDER:
        s = per_task[task]
        print(f"{task:11} {s['accuracy_pct']:>6} "
              f"{str(s['mean_latency_ms'] or '-'):>9} "
              f"{str(s['p50_latency_ms'] or '-'):>8} "
              f"{str(s['p95_latency_ms'] or '-'):>8} "
              f"{str(s['mean_tokens_per_sec'] or '-'):>7} "
              f"{s['errors']:>4}")
    print("-" * 78)
    print(f"{'OVERALL':11} {overall['accuracy_pct']:>6} "
          f"{str(overall['mean_latency_ms'] or '-'):>9} "
          f"{str(overall['p50_latency_ms'] or '-'):>8} "
          f"{str(overall['p95_latency_ms'] or '-'):>8} "
          f"{str(overall['mean_tokens_per_sec'] or '-'):>7} "
          f"{overall['errors']:>4}")
    print(line + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="NOCgentic model benchmark harness")
    ap.add_argument("--provider", default=None, help="Override LLM_PROVIDER (gemini|openrouter|local)")
    ap.add_argument("--model", default=None, help="Override model name for the active provider")
    ap.add_argument("--today", default=None, help="Partition date YYYY-MM-DD for NL->SQL (default from cases)")
    ap.add_argument("--dry-run", action="store_true",
                    help="No network: stub llm_complete + import-time deps. Proves scoring/timing/output.")
    ap.add_argument("--dry-mode", default="good", choices=["good", "bad"],
                    help="Dry-run stub behavior: 'good' plausible outputs, 'bad' junk (must score low).")
    ap.add_argument("--cases", default=str(BENCH_DIR / "cases.json"), help="Path to cases file")
    args = ap.parse_args()

    if args.provider:
        os.environ["LLM_PROVIDER"] = args.provider

    if args.dry_run:
        _install_import_stubs()

    with open(args.cases) as f:
        cases = json.load(f)
    today = args.today or cases.get("_meta", {}).get("today", "2026-07-22")

    try:
        real = RealBits()
    except Exception as exc:
        print(f"FATAL: could not import real prompts / llm_complete: {exc}", file=sys.stderr)
        if not args.dry_run:
            print("Hint: run inside the agent venv (langchain etc.), or use --dry-run.", file=sys.stderr)
        return 2

    # Resolve provider + model labels for the results filename.
    provider = (args.provider or os.getenv("LLM_PROVIDER", "gemini")).lower()
    if args.model:
        model = args.model
    elif provider == "gemini":
        model = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
    elif provider == "local":
        model = os.getenv("LOCAL_LLM_MODEL", "local-model")
    else:
        model = os.getenv("OPENROUTER_MODEL", "anthropic/claude-3-haiku")

    if args.dry_run:
        provider = f"dryrun-{args.dry_mode}"
        model = "stub"
        complete = make_stub_complete(args.dry_mode)
    else:
        # Real path: pass model+provider through to the REAL llm_complete so the
        # exact app code path runs. thinking_budget/max_tokens set per task.
        async def complete(system_prompt, user_content, **kw):
            return await real.llm_complete(
                system_prompt=system_prompt,
                user_content=user_content,
                model=args.model,
                provider=(args.provider or None),
                **kw,
            )

    print(f"Running benchmark: provider={provider} model={model} "
          f"cases={sum(len(cases.get(t, [])) for t in TASK_ORDER)}")

    results = asyncio.run(run_all(real, cases, complete, today))

    per_task = {t: summarize_task(results[t]) for t in TASK_ORDER}
    all_rows = [r for t in TASK_ORDER for r in results[t]]
    overall = summarize_task(all_rows)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_model = re.sub(r"[^A-Za-z0-9._-]", "_", model)
    safe_provider = re.sub(r"[^A-Za-z0-9._-]", "_", provider)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / f"{safe_provider}_{safe_model}_{ts}.json"

    payload = {
        "meta": {
            "provider": provider,
            "model": model,
            "timestamp_utc": ts,
            "today_partition": today,
            "dry_run": bool(args.dry_run),
            "env": {
                "LLM_PROVIDER": os.getenv("LLM_PROVIDER"),
                "GEMINI_MODEL": os.getenv("GEMINI_MODEL"),
                "LOCAL_LLM_BASE_URL": os.getenv("LOCAL_LLM_BASE_URL"),
                "LOCAL_LLM_MODEL": os.getenv("LOCAL_LLM_MODEL"),
            },
        },
        "per_task": per_task,
        "overall": overall,
        "results": results,
    }
    with open(out_path, "w") as f:
        json.dump(payload, f, indent=2, default=str)

    print_summary_table(provider, model, per_task, overall)
    print(f"Results written to: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
