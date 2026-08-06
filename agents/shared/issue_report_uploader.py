"""
issue_report_uploader.py — uploads a "Report Issue" screenshot + note to S3.

Same bucket as the trace archive (s3_span_exporter.py), different prefix, so
audit-monitor (which polls AUDIT_PREFIX=nocgentic/traces) never sees these and
a bucket listing keeps the two data sets apart.

Key layout:
    s3://{bucket}/{prefix}/dt=YYYY-MM-DD/<ts>-<uuid>.json

Environment variables:
    ISSUE_REPORT_S3_BUCKET  — bucket name (default: same as TRACE_S3_BUCKET / blackhatnoc)
    ISSUE_REPORT_S3_PREFIX  — key prefix (default: nocgentic/issue-reports)
    ISSUE_REPORT_S3_REGION  — region (default: same fallback chain as trace export)
"""

from __future__ import annotations

import base64
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import boto3

logger = logging.getLogger(__name__)

DEFAULT_BUCKET = os.getenv("ISSUE_REPORT_S3_BUCKET", os.getenv("TRACE_S3_BUCKET", "blackhatnoc"))
DEFAULT_PREFIX = os.getenv("ISSUE_REPORT_S3_PREFIX", "nocgentic/issue-reports").strip("/")
DEFAULT_REGION = os.getenv(
    "ISSUE_REPORT_S3_REGION",
    os.getenv("TRACE_S3_REGION", os.getenv("S3_REGION", os.getenv("AWS_REGION", "us-east-2"))),
)

# A screenshot data URL bounded at the web-server route; re-checked here so a
# caller that skips the web-server route can't push an unbounded blob into S3.
MAX_IMAGE_DATA_URL_LEN = 8_000_000


def _get_client():
    """Fresh boto3 client per upload — see s3_span_exporter._get_client() /
    athena_client._get_athena() for why we intentionally don't cache one."""
    session_kwargs: dict[str, str] = {}
    profile = os.getenv("AWS_PROFILE")
    if profile:
        session_kwargs["profile_name"] = profile
    session = boto3.Session(region_name=DEFAULT_REGION, **session_kwargs)
    return session.client("s3")


def _build_key() -> str:
    now = datetime.now(timezone.utc)
    dt = now.strftime("%Y-%m-%d")
    ts = now.strftime("%Y%m%dT%H%M%S")
    rnd = uuid.uuid4().hex[:8]
    return f"{DEFAULT_PREFIX}/dt={dt}/{ts}-{rnd}.json"


def upload_issue_report(
    note: str,
    image_data_url: str | None,
    view: str,
    path: str | None,
    client_info: dict[str, Any] | None,
) -> str:
    """Uploads one report as a JSON object (screenshot inline as base64).

    Returns the S3 key written. Raises on any failure — the caller (the
    /report-issue route) decides how to surface that to the web-server.

    NOTE: only `note` is scrubbed (credscrub.scrub_secrets, by the caller)
    before this runs. `image_data_url` is uploaded verbatim — a screenshot is
    pixels, not scrubbable text, so it carries whatever was on screen at
    capture time as-is. This is an accepted gap, not an oversight: unlike
    chat answers (sanitized before render), a live alert-detail popup's raw
    vendor `description` text or any other on-screen content is not filtered
    before it can appear in a screenshot.
    """
    image_b64: str | None = None
    image_content_type: str | None = None
    if image_data_url:
        if len(image_data_url) > MAX_IMAGE_DATA_URL_LEN:
            raise ValueError("image data URL too large")
        header, _, b64_body = image_data_url.partition(",")
        if not header.startswith("data:image/") or ";base64" not in header:
            raise ValueError("image must be a base64 image data URL")
        image_content_type = header[len("data:"):].split(";", 1)[0]
        # Validate it's actually base64 before we ship it anywhere.
        base64.b64decode(b64_body, validate=True)
        image_b64 = b64_body

    record = {
        "note": note[:1000],
        "view": view,
        "path": path,
        "client": client_info or {},
        "reported_at": datetime.now(timezone.utc).isoformat(),
        "image_content_type": image_content_type,
        "image_base64": image_b64,
    }

    key = _build_key()
    _get_client().put_object(
        Bucket=DEFAULT_BUCKET,
        Key=key,
        Body=json.dumps(record, ensure_ascii=False).encode("utf-8"),
        ContentType="application/json",
    )
    return key
