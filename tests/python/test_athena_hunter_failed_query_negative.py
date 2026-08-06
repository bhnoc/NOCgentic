"""Regression (QA sweep 10, FF10-003): a query that FAILED entirely (an
Athena error, zero successful query_results) must not read as a confident
negative with a fabricated time window.

SYSTEM_PROMPT already tells the model not to do this, but the local/AQLight
lane violated it live: "is the CTF network talking to the sponsor booths at
all" hit an "Out-of-scope IP prefix" error (sql_queries_executed=0) and still
answered "No activity from the CTF network... in the last hour (16:00-17:00)."
— a confident negative with a time window that no query ever covered, in
direct violation of the prompt's own rule. Prompt-only enforcement failed on a
smaller model, so llm_analyze() now overrides the model's text at the code
level whenever errors is non-empty and no query succeeded.
"""

import asyncio

from conftest import load_agent_main

_ah = load_agent_main("athena-hunter", "athena_hunter_main")


def _make_fake_llm(answer: str):
    async def _fake(*args, **kwargs):
        return answer
    return _fake


class TestFailedQueryNeverReadsAsNegative:
    def test_all_queries_failed_overrides_fabricated_negative(self, monkeypatch):
        # Exactly the live-caught shape: a confident negative + a fabricated
        # window, from a model that ignored the prompt's failed-query rule.
        bad_answer = (
            "## Answer\nNo activity from the CTF network to the sponsor booths "
            "in the last hour (16:00-17:00). The lookup for sponsor booth IPs "
            "could not be completed.\n\n```json\n{\"confidence\": 0.7}\n```"
        )
        monkeypatch.setattr(_ah, "llm_complete", _make_fake_llm(bad_answer))
        ctx = {
            "query_results": [],
            "errors": [{"sql": "SELECT ...", "error": "Out-of-scope IP prefix in query: 192.168.1"}],
            "total_rows": 0,
            "total_query_time_ms": 0,
        }
        answer, confidence = asyncio.run(_ah.llm_analyze("is the CTF network talking to the sponsor booths", ctx))

        assert "16:00-17:00" not in answer
        assert "No activity" not in answer
        assert confidence <= 0.2

    def test_successful_zero_row_query_is_left_alone(self, monkeypatch):
        """The override must only fire when NOTHING succeeded — a query that
        actually ran and found 0 rows is allowed to name its window."""
        good_answer = (
            "## Answer\nNo activity to Russia in the last hour (16:00-17:00).\n\n"
            "```json\n{\"confidence\": 0.2}\n```"
        )
        monkeypatch.setattr(_ah, "llm_complete", _make_fake_llm(good_answer))
        ctx = {
            "query_results": [{"sql": "SELECT ...", "rows": [], "row_count": 0,
                                "execution_time_ms": 100, "data_scanned_mb": 1.0}],
            "errors": [],
            "total_rows": 0,
            "total_query_time_ms": 100,
        }
        answer, confidence = asyncio.run(_ah.llm_analyze("who is talking to russia", ctx))

        assert "16:00-17:00" in answer
        assert confidence == 0.2

    def test_partial_success_with_some_errors_is_left_alone(self, monkeypatch):
        """Some queries succeeded, some failed: the model's own text stands,
        the override only fires when EVERY query failed."""
        answer_text = (
            "## Answer\nHost 1.2.3.4 made 10 connections in the last hour.\n\n"
            "```json\n{\"confidence\": 0.6}\n```"
        )
        monkeypatch.setattr(_ah, "llm_complete", _make_fake_llm(answer_text))
        ctx = {
            "query_results": [{"sql": "SELECT ...", "rows": [{"a": 1}], "row_count": 1,
                                "execution_time_ms": 100, "data_scanned_mb": 1.0}],
            "errors": [{"sql": "SELECT ...", "error": "TIMEOUT"}],
            "total_rows": 1,
            "total_query_time_ms": 100,
        }
        answer, confidence = asyncio.run(_ah.llm_analyze("test query", ctx))

        assert "10 connections" in answer
        assert confidence == 0.6
