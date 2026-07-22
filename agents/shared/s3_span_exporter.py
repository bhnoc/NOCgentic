"""
s3_span_exporter.py — OpenTelemetry SpanExporter that gzips NDJSON span batches
and uploads them to S3 so we have a permanent audit trail of every agent
interaction (including LangSmith-emitted LLM prompts + completions).

Key layout:
    s3://{bucket}/{prefix}/service=<svc>/dt=YYYY-MM-DD/hour=HH/<ts>-<uuid>.jsonl.gz

The Hive-style partitions let Athena query the archive directly.

Environment variables:
    TRACE_S3_BUCKET   — bucket name (default: blackhat-pope-dev-logs)
    TRACE_S3_PREFIX   — key prefix (default: bh-asia-26/aing-trace)
    TRACE_S3_REGION   — region (default: S3_REGION or us-west-2)
"""

from __future__ import annotations

import gzip
import io
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Sequence

import boto3

from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

logger = logging.getLogger(__name__)

DEFAULT_BUCKET = os.getenv("TRACE_S3_BUCKET", "blackhat-pope-dev-logs")
DEFAULT_PREFIX = os.getenv("TRACE_S3_PREFIX", "bh-asia-26/aing-trace").strip("/")
DEFAULT_REGION = os.getenv(
    "TRACE_S3_REGION",
    os.getenv("S3_REGION", os.getenv("AWS_REGION", "us-west-2")),
)


def _span_to_dict(span: ReadableSpan) -> dict[str, Any]:
    """Convert a ReadableSpan into a JSON-serialisable dict with GenAI + LangSmith attrs intact."""
    ctx = span.get_span_context()
    parent = span.parent
    status = span.status
    resource_attrs = dict(span.resource.attributes) if span.resource else {}

    start_ns = span.start_time or 0
    end_ns = span.end_time or 0
    duration_ms = (end_ns - start_ns) / 1_000_000 if end_ns and start_ns else None

    return {
        "name": span.name,
        "trace_id": f"{ctx.trace_id:032x}" if ctx and ctx.trace_id else None,
        "span_id": f"{ctx.span_id:016x}" if ctx and ctx.span_id else None,
        "parent_span_id": f"{parent.span_id:016x}" if parent else None,
        "kind": str(span.kind).split(".")[-1] if span.kind else None,
        "start_time": _ns_to_iso(start_ns),
        "end_time": _ns_to_iso(end_ns),
        "duration_ms": duration_ms,
        "status_code": str(status.status_code).split(".")[-1] if status else None,
        "status_description": status.description if status else None,
        "attributes": _serialize(dict(span.attributes or {})),
        "events": [
            {
                "name": ev.name,
                "timestamp": _ns_to_iso(ev.timestamp),
                "attributes": _serialize(dict(ev.attributes or {})),
            }
            for ev in (span.events or [])
        ],
        "links": [
            {
                "trace_id": f"{link.context.trace_id:032x}",
                "span_id": f"{link.context.span_id:016x}",
                "attributes": _serialize(dict(link.attributes or {})),
            }
            for link in (span.links or [])
        ],
        "resource": _serialize(resource_attrs),
        "instrumentation_scope": {
            "name": span.instrumentation_scope.name if span.instrumentation_scope else None,
            "version": span.instrumentation_scope.version if span.instrumentation_scope else None,
        } if span.instrumentation_scope else None,
    }


def _serialize(obj: Any) -> Any:
    """Best-effort serialise attribute values (handles bytes, tuples, sets, datetimes)."""
    if isinstance(obj, dict):
        return {str(k): _serialize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_serialize(v) for v in obj]
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8", errors="replace")
        except Exception:
            return repr(obj)
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


def _ns_to_iso(ns: int) -> str | None:
    if not ns:
        return None
    return datetime.fromtimestamp(ns / 1_000_000_000, tz=timezone.utc).isoformat()


class S3SpanExporter(SpanExporter):
    """Batch-upload spans as gzipped NDJSON to S3."""

    def __init__(
        self,
        service_name: str,
        bucket: str = DEFAULT_BUCKET,
        prefix: str = DEFAULT_PREFIX,
        region: str = DEFAULT_REGION,
    ) -> None:
        self.service_name = service_name
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.region = region
        self._shutdown = False

    def _get_client(self):
        """Fresh boto3 client per upload — see athena_client._get_athena() for
        rationale on why we intentionally don't cache."""
        session_kwargs: dict[str, str] = {}
        profile = os.getenv("AWS_PROFILE")
        if profile:
            session_kwargs["profile_name"] = profile
        session = boto3.Session(region_name=self.region, **session_kwargs)
        return session.client("s3")

    def _build_key(self) -> str:
        now = datetime.now(timezone.utc)
        dt = now.strftime("%Y-%m-%d")
        hour = now.strftime("%H")
        ts = now.strftime("%Y%m%dT%H%M%S")
        rnd = uuid.uuid4().hex[:8]
        return (
            f"{self.prefix}/service={self.service_name}/dt={dt}/hour={hour}/"
            f"{self.service_name}-{ts}-{rnd}.jsonl.gz"
        )

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        if self._shutdown or not spans:
            return SpanExportResult.SUCCESS

        try:
            buf = io.BytesIO()
            with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
                for span in spans:
                    try:
                        line = json.dumps(_span_to_dict(span), default=str, ensure_ascii=False)
                    except Exception as exc:
                        line = json.dumps({"_encode_error": str(exc), "span_name": getattr(span, "name", "?")})
                    gz.write(line.encode("utf-8") + b"\n")

            key = self._build_key()
            self._get_client().put_object(
                Bucket=self.bucket,
                Key=key,
                Body=buf.getvalue(),
                ContentType="application/x-ndjson",
                ContentEncoding="gzip",
            )
            return SpanExportResult.SUCCESS
        except Exception as exc:
            logger.warning("S3 span export failed: %s", exc)
            return SpanExportResult.FAILURE

    def shutdown(self) -> None:
        self._shutdown = True

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True
