"""Regression: a failed Athena query must not leak the Glue database/table name
into the LLM analysis context (and from there into the answer and the
orchestrator's Next Steps hints).

Root cause: Athena engine errors (COLUMN_NOT_FOUND / TABLE_NOT_FOUND) quote the
fully catalog-qualified name back, e.g.
  "Table 'awsdatacatalog.blackhatnoc_glue.conn' does not exist"
That raw exception string went straight into ctx["errors"], which
llm_analyze() dumps verbatim into the LLM prompt. The LLM then paraphrased it
into the answer's "Next Steps" section, and the orchestrator's hint generator
(which just summarizes the first 800 chars of the answer) reproduced it as a
hint like "show tables in blackhatnoc_glue".
"""

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
    spec = importlib.util.spec_from_file_location("athena_hunter_main_scrub", path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:
        pytest.skip(f"athena-hunter deps unavailable: {exc}")
    return mod


class TestScrubEngineError:
    def test_catalog_qualified_table_error_is_scrubbed(self, athena_mod):
        raw = (
            "Athena query FAILED: SYNTAX_ERROR: line 1:8: "
            "Table 'awsdatacatalog.blackhatnoc_glue.conn' does not exist"
        )
        scrubbed = athena_mod._scrub_engine_error(raw)
        assert "blackhatnoc_glue" not in scrubbed
        assert "conn" in scrubbed  # keep the rest of the diagnostic intact

    def test_bare_database_name_without_catalog_prefix_is_scrubbed(self, athena_mod):
        raw = "Athena query FAILED: Column 'orig_h' cannot be resolved in blackhatnoc_glue.conn"
        scrubbed = athena_mod._scrub_engine_error(raw)
        assert "blackhatnoc_glue" not in scrubbed

    def test_error_without_schema_name_is_left_alone(self, athena_mod):
        raw = "Athena query FAILED: TIMEOUT: query exceeded 60000ms"
        assert athena_mod._scrub_engine_error(raw) == raw


class TestGatherContextRecordsScrubbedErrorOnly:
    def test_a_column_not_found_failure_never_reaches_ctx_with_the_db_name(
        self, athena_mod, monkeypatch,
    ):
        async def mock_generate_sql(query, classified, today, lane=None):
            return ["SELECT orig_h FROM conn LIMIT 10"]

        async def mock_execute_sql(sql):
            raise RuntimeError(
                "Athena query FAILED: Column 'orig_h' cannot be resolved "
                "in awsdatacatalog.blackhatnoc_glue.conn"
            )

        monkeypatch.setattr(athena_mod, "generate_sql", mock_generate_sql)
        monkeypatch.setattr(athena_mod, "execute_custom_sql", mock_execute_sql)

        ctx = asyncio.run(athena_mod.gather_athena_context([], "all connections for 10.1.2.3"))

        assert len(ctx["errors"]) == 1
        assert "blackhatnoc_glue" not in ctx["errors"][0]["error"]
