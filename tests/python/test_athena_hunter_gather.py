"""Regression test for Athena Hunter concurrent query gathering via asyncio.gather."""

import asyncio
import re
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
        async def mock_generate_sql(query, classified, today, lane=None):
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


class TestPartitionGuardTestsForAPredicate:
    """`if "dt" not in sql.lower()` is a SUBSTRING test standing in for "does this query
    filter the partition". Any query containing those two letters anywhere satisfies it
    and skips injection, then runs UNPARTITIONED across the whole projected range
    (2026-04-01..12-31) -- so a question about "today" silently returns all-time rows,
    and does it by scanning every partition.
    """

    # A word-boundaried dt PREDICATE, mirroring the module's _DT_PREDICATE.
    PATTERN = re.compile(
        r"(?:^|[^a-z0-9_])dt\s*(?:=|<|>|!=|<>|\bIN\b|\bBETWEEN\b)", re.IGNORECASE)

    @pytest.mark.parametrize("sql,has_predicate", [
        # Real partition filters -> leave alone.
        ("SELECT * FROM conn WHERE dt = '2026-08-01'", True),
        ("SELECT * FROM conn WHERE dt IN ('2026-08-01','2026-08-02')", True),
        ("SELECT * FROM ssl WHERE dt >= '2026-08-01'", True),
        ("SELECT * FROM c WHERE c.dt = '2026-08-01'", True),
        # THE TRAPS: contain the letters "dt" but filter nothing.
        ("SELECT SUM(orig_bytes) AS bandwidth FROM conn", False),
        ("SELECT * FROM conn WHERE service = 'dtls'", False),
        ("SELECT created_dt FROM files", False),
        ("SELECT dt, COUNT(*) FROM conn GROUP BY dt", False),
    ])
    def test_only_a_real_predicate_counts(self, sql, has_predicate):
        assert bool(self.PATTERN.search(sql)) is has_predicate

    def test_the_module_no_longer_uses_the_substring_test(self):
        path = os.path.join(_ROOT, "agents", "athena-hunter", "main.py")
        # Comments quote the old form to explain why it was wrong, so strip them first.
        code = "\n".join(l for l in open(path).read().splitlines()
                         if not l.strip().startswith("#"))
        assert '"dt" not in sql.lower()' not in code, (
            "the substring partition guard is back; 'bandwidth' would satisfy it")
        assert "_DT_PREDICATE.search(sql)" in code
