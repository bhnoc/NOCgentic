"""Regression: Next Steps hints must never be schema/SQL introspection text.

Bug report: hints occasionally surfaced something like "show tables in
blackhatnoc_glue" instead of a domain follow-up ("all sessions/connections for
IP X"). Root cause traced to a failed Athena query leaking its catalog-
qualified engine error into the answer text that generate_hints() summarizes
(fixed separately in athena-hunter/main.py::_scrub_engine_error). This test
locks in the orchestrator's own defense-in-depth filter, _strip_schema_noise,
which drops any schema/SQL-shaped hint regardless of which upstream agent
produced it.
"""

import importlib.util
import os
import sys

import pytest

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(_ROOT, "agents", "shared"))


@pytest.fixture(scope="module")
def orch_mod():
    path = os.path.join(_ROOT, "agents", "orchestrator", "main.py")
    spec = importlib.util.spec_from_file_location("orchestrator_main_hints", path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:
        pytest.skip(f"orchestrator deps unavailable: {exc}")
    return mod


class TestStripSchemaNoise:
    def test_drops_show_tables_hint(self, orch_mod):
        hints = [
            "show tables in blackhatnoc_glue",
            "Show all connections for this IP in the last 24h",
        ]
        result = orch_mod._strip_schema_noise(hints)
        assert result == ["Show all connections for this IP in the last 24h"]

    def test_drops_glue_database_name_even_without_show_tables(self, orch_mod):
        hints = ["Check blackhatnoc_glue for related sessions"]
        assert orch_mod._strip_schema_noise(hints) == []

    def test_drops_information_schema_and_sql_error_language(self, orch_mod):
        hints = [
            "Query information_schema for related tables",
            "Investigate the COLUMN_NOT_FOUND error further",
            "Find top talkers by bytes transferred today",
        ]
        assert orch_mod._strip_schema_noise(hints) == [
            "Find top talkers by bytes transferred today"
        ]

    def test_legitimate_domain_hints_survive_untouched(self, orch_mod):
        hints = [
            "Show all connections for this IP in the last 24h",
            "Query DNS logs for suspicious domains in the last 24h",
            "Find top talkers by bytes transferred today",
            "Check SSL/TLS connections to unusual server names",
            "Search alerts for high-severity events this week",
        ]
        assert orch_mod._strip_schema_noise(hints) == hints
