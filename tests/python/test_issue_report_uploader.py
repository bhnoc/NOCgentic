"""Regression tests for agents/shared/issue_report_uploader.py

Locks in:
  * key layout uses ISSUE_REPORT_S3_PREFIX, never the trace prefix (so
    audit-monitor, which polls AUDIT_PREFIX=nocgentic/traces, never sees these).
  * a fresh boto3 client is built per upload (no module-level cache) -- same
    rationale as s3_span_exporter._get_client / athena_client._get_athena.
  * malformed image data URLs are rejected before any S3 call.
"""

from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

import issue_report_uploader as iru


def test_default_prefix_is_not_the_trace_prefix():
    assert iru.DEFAULT_PREFIX == "nocgentic/issue-reports"
    assert "traces" not in iru.DEFAULT_PREFIX


def test_build_key_uses_issue_report_prefix():
    key = iru._build_key()
    assert key.startswith("nocgentic/issue-reports/dt=")
    assert key.endswith(".json")


def test_upload_builds_fresh_client_per_call():
    """Each call to upload_issue_report must obtain its own boto3 client
    (never a module-level cached one) -- caching is exactly the bug pattern
    that caused ExpiredToken failures on EC2 instance-role containers."""
    calls = []

    def fake_get_client():
        client = MagicMock()
        calls.append(client)
        return client

    with patch.object(iru, "_get_client", side_effect=fake_get_client):
        iru.upload_issue_report("first", None, "chat", None, None)
        iru.upload_issue_report("second", None, "chat", None, None)

    assert len(calls) == 2
    assert calls[0] is not calls[1]
    calls[0].put_object.assert_called_once()
    calls[1].put_object.assert_called_once()


def test_upload_rejects_non_data_url_image():
    with patch.object(iru, "_get_client") as get_client:
        try:
            iru.upload_issue_report("x", "https://evil.example/img.png", "chat", None, None)
            assert False, "expected ValueError"
        except ValueError:
            pass
    get_client.assert_not_called()


def test_upload_rejects_oversized_image():
    oversized = "data:image/png;base64," + "A" * (iru.MAX_IMAGE_DATA_URL_LEN + 1)
    with patch.object(iru, "_get_client") as get_client:
        try:
            iru.upload_issue_report("x", oversized, "chat", None, None)
            assert False, "expected ValueError"
        except ValueError:
            pass
    get_client.assert_not_called()


def test_upload_puts_valid_image_as_base64_body_field():
    raw_png_bytes = b"\x89PNG\r\n\x1a\n"
    b64 = base64.b64encode(raw_png_bytes).decode("ascii")
    data_url = f"data:image/png;base64,{b64}"

    client = MagicMock()
    with patch.object(iru, "_get_client", return_value=client):
        key = iru.upload_issue_report("note text", data_url, "hunt", "#threat-hunt", {"session_id": "s-1"})

    assert key.startswith("nocgentic/issue-reports/")
    put_kwargs = client.put_object.call_args.kwargs
    assert put_kwargs["Bucket"] == iru.DEFAULT_BUCKET
    assert put_kwargs["Key"] == key
    assert put_kwargs["ContentType"] == "application/json"
    body = put_kwargs["Body"].decode("utf-8")
    assert '"image_base64": "' + b64 + '"' in body
    assert '"view": "hunt"' in body
    assert '"session_id": "s-1"' in body
