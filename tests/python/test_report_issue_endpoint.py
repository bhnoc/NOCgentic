"""Orchestrator POST /report-issue: the wire path for the chat/hunt "Report
Issue" widget. Not a classified/routed intent -- called directly by
web-server's /api/v1/report-issue proxy, no admin bearer (unauthenticated
same-origin traffic from any visitor, like /query).
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from conftest import load_agent_main

_orch = load_agent_main("orchestrator", "orch_main")


@pytest.fixture
def client():
    return TestClient(_orch.app)


def test_report_issue_uploads_and_returns_key(client):
    with patch.object(_orch, "upload_issue_report", return_value="nocgentic/issue-reports/dt=2026-08-05/x.json") as up:
        r = client.post("/report-issue", json={"note": "chip overflow", "view": "chat"})

    assert r.status_code == 200
    assert r.json()["status"] == "received"
    assert r.json()["key"].startswith("nocgentic/issue-reports/")
    up.assert_called_once()
    _, kwargs = up.call_args
    assert kwargs["note"] == "chip overflow"
    assert kwargs["view"] == "chat"


def test_report_issue_scrubs_secrets_from_the_note_before_upload():
    """A user pasting a credential into the free-text blurb must not land in
    S3 verbatim -- same scrub path as query text before it reaches an LLM."""
    client = TestClient(_orch.app)
    with patch.object(_orch, "upload_issue_report", return_value="k") as up:
        client.post("/report-issue", json={"note": "password=SuperSecret123!", "view": "chat"})

    _, kwargs = up.call_args
    assert "SuperSecret123!" not in kwargs["note"]


def test_report_issue_502s_when_upload_fails(client):
    with patch.object(_orch, "upload_issue_report", side_effect=RuntimeError("s3 down")):
        r = client.post("/report-issue", json={"note": "x", "view": "chat"})

    assert r.status_code == 502


def test_report_issue_rejects_oversized_image(client):
    oversized = "data:image/png;base64," + "A" * 8_000_001
    r = client.post("/report-issue", json={"note": "x", "image": oversized, "view": "chat"})
    assert r.status_code == 422
