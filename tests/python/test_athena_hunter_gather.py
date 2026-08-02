"""Regression test for Athena Hunter concurrent query gathering via asyncio.gather."""

import asyncio
import importlib.util
import os
import sys

import pytest

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(_ROOT, "agents", "shared"))


@pytest.fixture(scope="module")
def athena_mod():
    path = os.path.join(_ROOT, "agents", "athena-hunter", "main.py")
    spec = importlib.util.spec_from_file_location("athena_hunter_main", path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:
        pytest.skip(f"athena-hunter deps unavailable: {exc}")
    return mod


class TestAthenaHunterGather:
    def test_gather_athena_context_concurrent_execution(self, athena_mod, monkeypatch):
        async def mock_generate_sql(query, classified, today):
            return [
                "SELECT 1 AS col LIMIT 10",
                "SELECT 2 AS col LIMIT 5",
            ]

        async def mock_execute_sql(sql):
            return [{"col": "val"}], {
                "execution_time_ms": 50,
                "data_scanned_mb": 1.5,
                "data_scanned_bytes": 1500000,
                "cached": False,
            }

        monkeypatch.setattr(athena_mod, "generate_sql", mock_generate_sql)
        monkeypatch.setattr(athena_mod, "execute_custom_sql", mock_execute_sql)

        ctx = asyncio.run(athena_mod.gather_athena_context([], "test query"))
        assert len(ctx["sql_queries"]) == 2
        assert len(ctx["query_results"]) == 2
        assert ctx["total_rows"] == 2
        assert ctx["total_query_time_ms"] == 100
