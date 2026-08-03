"""
Shared pytest fixtures / import-path bootstrap for the NOCgentic regression suite.

The agents are NOT a package: each `agents/<name>/main.py` does its own
`sys.path.insert(0, agents/shared)` at import time and then `import athena_client`
etc. by bare module name. We mirror that here so tests can `import athena_client`
or import a given agent's `main.py`.

Importing an agent `main.py` triggers side effects at module scope:
  * init_telemetry(...) ; would try to configure OTLP export / hit the network.
  * FastAPI app creation.
  * get_meter() instrument creation.
We neutralise the network/credential parts by forcing OTEL_ENABLED=false and
providing dummy LLM/AWS env BEFORE any agent import. LangChain is only imported
lazily inside llm_complete(), so importing main.py never needs a real key.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Env stubs; set before ANY agent import so module-level init_telemetry() is
# a no-op and no code path reaches the network or real credentials.
# ---------------------------------------------------------------------------
os.environ.setdefault("OTEL_ENABLED", "false")
os.environ.setdefault("OTEL_CONSOLE_TRACES", "false")
os.environ.setdefault("GEMINI_API_KEY", "test-dummy-key")
os.environ.setdefault("LLM_PROVIDER", "gemini")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
# thousandeyes: leave the token UNSET by default so gather_te_context's
# no-token guard is exercised where relevant; individual tests set it.

_REPO = Path(__file__).resolve().parents[2]
_AGENTS = _REPO / "agents"

# Put agents/shared first (bare-name imports: athena_client, llm_client, telemetry)
_SHARED = str(_AGENTS / "shared")
if _SHARED not in sys.path:
    sys.path.insert(0, _SHARED)

# Also expose the scripts/ dir for redate_slice.
_SCRIPTS = str(_REPO / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)


@pytest.fixture(autouse=True)
def _cold_te_cache():
    """Start every test with an empty thousandeyes-analyst TTL cache.

    That cache keys entries by `id(client)` for any non-httpx client, i.e. for
    every test stub. CPython recycles object addresses, so once a stub is freed
    a later, unrelated stub can be allocated at the same address and receive the
    dead stub's cached value while the 30s TTL is still open. The stub's .get is
    then never called and the test sees the *previous* test's payload.

    That made test_thousandeyes.py allocator- and order-dependent: green locally
    and in one CI run, red in the next, with test_fetch_all_tests_filters_disabled
    getting the [] cached by test_fetch_all_tests_empty_success_*. Both files that
    load the agent share one module (load_agent_main memoises via sys.modules), so
    the pollution crosses files and this lives in conftest rather than one module.

    Production is unaffected: a real httpx.AsyncClient takes the "" key prefix and
    never goes near id(). Keying on id() is still unsound and worth replacing.
    """
    te = sys.modules.get("te_main")
    if te is not None:
        te._te_cache.clear()
    yield


def load_agent_main(agent_dir_name: str, module_alias: str):
    """Import an agent's `main.py` under a unique module name.

    Each agent has its own top-level `main.py`; importing them all as `main`
    would collide, so we load each under an explicit alias. The agent's own
    `sys.path.insert(agents/shared)` still runs, which is fine (idempotent).
    """
    if module_alias in sys.modules:
        return sys.modules[module_alias]
    path = _AGENTS / agent_dir_name / "main.py"
    spec = importlib.util.spec_from_file_location(module_alias, path)
    assert spec and spec.loader, f"cannot load {path}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_alias] = mod
    spec.loader.exec_module(mod)
    return mod
