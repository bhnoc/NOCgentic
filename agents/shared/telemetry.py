"""
telemetry.py — OpenTelemetry setup for Manifold agent monitoring.

Call init_telemetry() ONCE at process startup, before any LLM or agent code runs.
Exports traces, metrics, and logs to Manifold's OTLP endpoint.
Log records are automatically correlated with the active trace/span.

Environment variables:
    OTEL_EXPORTER_OTLP_ENDPOINT  — Manifold OTLP base URL (default: https://blackcap.app.manifoldsecurity.io:4318)
    OTEL_EXPORTER_OTLP_API_KEY   — Manifold API key
    OTEL_SERVICE_NAME            — Service name tag (default: bhnocgentic-agent)
    OTEL_ENABLED                 — Set to "false" to disable (default: "true")
    OTEL_SAMPLE_RATE             — Trace sampling ratio 0.0-1.0 (default: "1.0" = 100%)
    OTEL_METRICS_INTERVAL_MS     — Metric flush interval in ms (default: "60000")
    OTEL_LOG_LEVEL               — Minimum Python log level to export (default: "INFO")
    OTEL_CONSOLE_TRACES          — Set to "true" to also print spans to stderr (default: "true")
"""

from __future__ import annotations

import logging
import os
import re
import sys

logger = logging.getLogger(__name__)

_tracer = None
_meter = None
_initialized = False


# ---------------------------------------------------------------------------
# Redaction — scrub PII / internal IPs / secrets before anything leaves the
# process. The per-agent sanitize() only runs on the LLM *input* string; raw
# prompts, completions, span attributes and logged SQL still reach the external
# OTLP endpoint (Manifold), the permanent S3 archive, and the console. Redact
# at the export boundary so nothing sensitive is shipped. Patterns mirror the
# per-agent sanitize() (see agents/*/main.py).
# ---------------------------------------------------------------------------

_RE_INTERNAL_IP = re.compile(
    r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"
)
_RE_SECRET_TOKEN = re.compile(r"\b[A-Za-z0-9+/]{40,}\b")
_RE_PASSWORD = re.compile(r"(?i)password\s*[:=]\s*\S+")
_RE_API_KEY = re.compile(r"(?i)api[_-]?key\s*[:=]\s*\S+")
_RE_BEARER = re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+")

# Span attribute keys that may carry sensitive free text (LLM prompts/
# completions, HTTP bodies, raw SQL). Matched case-insensitively by substring.
_SENSITIVE_ATTR_HINTS = (
    "gen_ai.prompt",
    "gen_ai.completion",
    "prompt",
    "completion",
    "http.request.body",
    "http.response.body",
    "db.statement",
    "sql",
)


def _redact(text: str) -> str:
    """Scrub internal IPs, secrets, passwords and API keys from free text."""
    if not isinstance(text, str) or not text:
        return text
    text = _RE_INTERNAL_IP.sub("[INTERNAL-IP]", text)
    text = _RE_SECRET_TOKEN.sub("[REDACTED-SECRET]", text)
    text = _RE_PASSWORD.sub("password: [REDACTED]", text)
    text = _RE_API_KEY.sub("api_key: [REDACTED]", text)
    text = _RE_BEARER.sub("bearer [REDACTED]", text)
    return text


def _is_sensitive_attr(key: str) -> bool:
    k = key.lower()
    return any(hint in k for hint in _SENSITIVE_ATTR_HINTS)


class _RedactingLogFilter(logging.Filter):
    """Redact sensitive text from log records before they hit any handler.

    Attached to the OTLP LoggingHandler so raw SQL / internal IPs in log lines
    (e.g. athena_client "Athena query started") never reach Manifold. Mutates
    the already-formatted message so downstream handlers emit the scrubbed form.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
            redacted = _redact(msg)
            if redacted != msg:
                record.msg = redacted
                record.args = None
        except Exception:  # never drop a log line because redaction blew up
            pass
        return True


def _make_redacting_span_processor():
    """Return a SpanProcessor that scrubs sensitive span attributes on_end.

    Registered BEFORE the exporting BatchSpanProcessors so its in-place
    mutation of the (mutable) span attribute map is seen by the OTLP, S3 and
    console exporters. Defensive: any failure is swallowed so telemetry keeps
    flowing — we redact, we never drop spans.
    """
    from opentelemetry.sdk.trace import SpanProcessor

    class _RedactingSpanProcessor(SpanProcessor):
        def on_start(self, span, parent_context=None):  # noqa: D401
            pass

        def on_end(self, span) -> None:
            try:
                attrs = getattr(span, "_attributes", None)
                if attrs:
                    for key in list(attrs.keys()):
                        val = attrs[key]
                        if isinstance(val, str) and _is_sensitive_attr(key):
                            attrs[key] = _redact(val)
            except Exception:
                pass
            # LLM prompts/completions are frequently recorded as span EVENTS
            # (LangSmith / GenAI OTEL conventions), not span attributes, and the
            # S3 + OTLP exporters serialize event attributes verbatim. Walk each
            # event's attribute map and scrub via the SAME helpers. Kept in a
            # separate try so an events failure never affects attribute redaction
            # (or drops the span). event.attributes is a mutable mapping
            # (BoundedAttributes) in this SDK — mutate in place like _attributes.
            try:
                events = getattr(span, "_events", None) or getattr(span, "events", None)
                if not events:
                    return
                for event in events:
                    ev_attrs = getattr(event, "attributes", None)
                    if not ev_attrs:
                        continue
                    for key in list(ev_attrs.keys()):
                        val = ev_attrs[key]
                        if isinstance(val, str) and _is_sensitive_attr(key):
                            ev_attrs[key] = _redact(val)
            except Exception:
                pass

        def shutdown(self) -> None:
            pass

        def force_flush(self, timeout_millis: int = 30000) -> bool:
            return True

    return _RedactingSpanProcessor()


def _normalize_endpoint(endpoint: str) -> str:
    return endpoint.rstrip("/")


def init_telemetry(service_name: str | None = None) -> None:
    """
    Initialize OTel traces + metrics + logs, all pointing to Manifold.

    Safe to call multiple times — only the first call takes effect.
    Silently disables if OTEL_ENABLED=false or packages are missing.
    Python log records are automatically forwarded to /v1/logs with trace context.
    """
    global _tracer, _meter, _initialized

    if _initialized:
        return
    _initialized = True

    # Force basic logging so our init messages are visible even before
    # the calling module configures its own logging.
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
        force=False,
    )

    enabled = os.getenv("OTEL_ENABLED", "true").lower()
    if enabled in ("false", "0", "no"):
        logger.warning("OTEL_ENABLED=%s — OTel disabled", enabled)
        return

    endpoint = _normalize_endpoint(
        os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://blackcap.app.manifoldsecurity.io:4318")
    )
    api_key = os.getenv("OTEL_EXPORTER_OTLP_API_KEY", "")
    svc_name = service_name or os.getenv("OTEL_SERVICE_NAME", "bhnocgentic-agent")
    sample_rate = float(os.getenv("OTEL_SAMPLE_RATE", "1.0"))
    metrics_interval_ms = int(os.getenv("OTEL_METRICS_INTERVAL_MS", "60000"))
    log_level_name = os.getenv("OTEL_LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_name, logging.INFO)
    console_traces = os.getenv("OTEL_CONSOLE_TRACES", "true").lower() in ("true", "1", "yes")

    if not api_key:
        logger.warning("OTEL_EXPORTER_OTLP_API_KEY not set — OTel disabled")
        return

    auth_headers = {"Authorization": f"Bearer {api_key}"}

    try:
        from opentelemetry import trace, metrics
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import (
            BatchSpanProcessor,
            SimpleSpanProcessor,
            ConsoleSpanExporter,
        )
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    except ImportError as exc:
        logger.warning("OpenTelemetry core packages missing — OTel disabled (%s)", exc)
        return

    resource = Resource.create({"service.name": svc_name})

    # --- Traces ---
    if sample_rate < 1.0:
        try:
            from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased
            trace_provider = TracerProvider(
                resource=resource,
                sampler=ParentBased(TraceIdRatioBased(sample_rate)),
            )
        except ImportError:
            trace_provider = TracerProvider(resource=resource)
    else:
        trace_provider = TracerProvider(resource=resource)

    # Redacting processor MUST be registered first: processors fire in
    # registration order, and it mutates the span's attribute map in place so
    # every downstream exporter (OTLP/Manifold, S3 archive, console) sees the
    # scrubbed prompts/completions/SQL rather than the raw values.
    try:
        trace_provider.add_span_processor(_make_redacting_span_processor())
    except Exception as exc:
        logger.warning("Redacting span processor failed to initialise: %s", exc)

    # OTLP exporter → Manifold
    trace_provider.add_span_processor(
        BatchSpanProcessor(
            OTLPSpanExporter(endpoint=f"{endpoint}/v1/traces", headers=auth_headers)
        )
    )

    # S3 audit-trail exporter → s3://blackhat-pope-dev-logs/bh-asia-26/aing-trace/
    # Captures every span (FastAPI, httpx, Athena, and LangSmith LLM spans) as
    # gzipped NDJSON so we have a permanent record of every agent interaction.
    if os.getenv("TRACE_S3_ENABLED", "true").lower() in ("true", "1", "yes"):
        try:
            from s3_span_exporter import S3SpanExporter  # noqa: WPS433
            trace_provider.add_span_processor(
                BatchSpanProcessor(
                    S3SpanExporter(service_name=svc_name),
                    max_export_batch_size=256,
                    schedule_delay_millis=5000,
                )
            )
            logger.info(
                "S3 span exporter enabled — spans archived to s3://%s/%s/service=%s/",
                os.getenv("TRACE_S3_BUCKET", "blackhat-pope-dev-logs"),
                os.getenv("TRACE_S3_PREFIX", "bh-asia-26/aing-trace"),
                svc_name,
            )
        except Exception as exc:
            logger.warning("S3 span exporter failed to initialise: %s", exc)

    # Console exporter → docker logs (so you can see spans via `docker logs`)
    if console_traces:
        trace_provider.add_span_processor(
            SimpleSpanProcessor(ConsoleSpanExporter(out=sys.stderr))
        )
        logger.info("Console span exporter enabled — spans will appear in stderr/docker logs")

    trace.set_tracer_provider(trace_provider)
    _tracer = trace.get_tracer(svc_name)

    # --- LangSmith OTEL integration ---
    # Set these BEFORE any LangChain import so LangSmith uses our TracerProvider
    # to export LLM traces (prompts, completions, token usage) via OTEL.
    os.environ.setdefault("LANGSMITH_TRACING", "true")
    os.environ.setdefault("LANGSMITH_OTEL_ENABLED", "true")
    # Prevent LangSmith from also trying to send to its cloud API (we only want OTEL)
    os.environ.setdefault("LANGCHAIN_TRACING_V2", "false")
    logger.info("LangSmith OTEL enabled — LangChain LLM traces will export via our TracerProvider")

    # --- Metrics ---
    meter_provider = MeterProvider(
        resource=resource,
        metric_readers=[
            PeriodicExportingMetricReader(
                OTLPMetricExporter(endpoint=f"{endpoint}/v1/metrics", headers=auth_headers),
                export_interval_millis=max(metrics_interval_ms, 1000),
            )
        ],
    )
    metrics.set_meter_provider(meter_provider)
    _meter = metrics.get_meter(svc_name)

    # --- Logs ---
    _setup_log_export(endpoint, auth_headers, resource, svc_name, log_level)

    # --- Auto-instrumentation for FastAPI + httpx (trace context propagation) ---
    _setup_auto_instrumentation()

    logger.info(
        "OTel initialized → %s (service=%s, sample_rate=%.2f, metrics_interval=%dms, log_level=%s, console=%s)",
        endpoint, svc_name, sample_rate, metrics_interval_ms, log_level_name, console_traces,
    )


def _setup_log_export(
    endpoint: str,
    auth_headers: dict,
    resource: object,
    svc_name: str,
    log_level: int,
) -> None:
    """Attach an OTLP log handler to the root Python logger."""
    try:
        from opentelemetry.sdk.logs import LoggerProvider, LoggingHandler
        from opentelemetry.sdk.logs.export import BatchLogRecordProcessor
        from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
        from opentelemetry._logs import set_logger_provider
    except ImportError:
        try:
            # Older SDK path
            from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
            from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
            from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
            from opentelemetry._logs import set_logger_provider
        except ImportError as exc:
            logging.getLogger(__name__).warning(
                "OTel log export unavailable — logs will not be shipped to Manifold (%s)", exc
            )
            return

    log_provider = LoggerProvider(resource=resource)
    log_provider.add_log_record_processor(
        BatchLogRecordProcessor(
            OTLPLogExporter(endpoint=f"{endpoint}/v1/logs", headers=auth_headers)
        )
    )
    set_logger_provider(log_provider)

    # Attach to root logger — captures all INFO+ logs from all modules.
    # Logs are automatically tagged with the active trace_id and span_id.
    handler = LoggingHandler(level=log_level, logger_provider=log_provider)
    # Redact internal IPs / secrets / raw SQL from log records before they are
    # shipped to Manifold's /v1/logs endpoint.
    handler.addFilter(_RedactingLogFilter())
    logging.getLogger().addHandler(handler)


def _setup_auto_instrumentation() -> None:
    """Enable auto-instrumentation for httpx.

    FastAPI instrumentation must be done per-app via instrument_app() — see below.
    httpx instrumentation is global and injects traceparent into all outgoing requests.
    LLM tracing is handled by LangSmith OTEL (LANGSMITH_TRACING + LANGSMITH_OTEL_ENABLED).
    """
    # httpx instrumentation — injects traceparent into outgoing requests
    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
        HTTPXClientInstrumentor().instrument()
        logger.info("httpx auto-instrumentation enabled (outbound trace propagation)")
    except ImportError:
        logger.debug("opentelemetry-instrumentation-httpx not installed — skipping")
    except Exception as exc:
        logger.warning("httpx instrumentation failed: %s", exc)


def instrument_fastapi_app(app) -> None:
    """Instrument a FastAPI app for inbound trace context extraction.

    Call this AFTER creating the FastAPI app:
        app = FastAPI(...)
        instrument_fastapi_app(app)

    This ensures incoming requests with traceparent headers create child spans
    linked to the caller's trace, enabling full distributed tracing.
    """
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        FastAPIInstrumentor.instrument_app(app)
        logger.info("FastAPI app instrumented for inbound trace propagation")
    except ImportError:
        logger.debug("opentelemetry-instrumentation-fastapi not installed — skipping")
    except Exception as exc:
        logger.warning("FastAPI app instrumentation failed: %s", exc)


def inject_trace_headers(headers: dict | None = None) -> dict:
    """Inject W3C traceparent/tracestate into an HTTP headers dict.

    Use this as a manual fallback when httpx auto-instrumentation is not available.
    Example: headers = inject_trace_headers({"Content-Type": "application/json"})
    """
    headers = dict(headers) if headers else {}
    try:
        from opentelemetry.propagate import inject
        inject(headers)
    except ImportError:
        pass
    return headers


def get_tracer():
    """Return the OTel tracer, or a no-op if not initialized."""
    global _tracer
    if _tracer is not None:
        return _tracer
    try:
        from opentelemetry import trace
        return trace.get_tracer("bhnocgentic-noop")
    except ImportError:
        return _NoOpTracer()


def get_meter():
    """Return the OTel meter, or a no-op if not initialized."""
    global _meter
    if _meter is not None:
        return _meter
    try:
        from opentelemetry import metrics
        return metrics.get_meter("bhnocgentic-noop")
    except ImportError:
        return _NoOpMeter()


# ---------------------------------------------------------------------------
# No-op fallbacks (when OTel packages are missing or disabled)
# ---------------------------------------------------------------------------

class _NoOpSpan:
    def set_attribute(self, key, value): pass
    def set_status(self, status): pass
    def record_exception(self, exc): pass
    def add_event(self, name, **kwargs): pass
    def __enter__(self): return self
    def __exit__(self, *args): pass


class _NoOpTracer:
    def start_as_current_span(self, name, **kwargs):
        return _NoOpSpan()


class _NoOpInstrument:
    def add(self, value, attributes=None): pass
    def record(self, value, attributes=None): pass


class _NoOpMeter:
    def create_counter(self, name, **kwargs): return _NoOpInstrument()
    def create_histogram(self, name, **kwargs): return _NoOpInstrument()
    def create_up_down_counter(self, name, **kwargs): return _NoOpInstrument()
    def create_observable_gauge(self, name, **kwargs): return _NoOpInstrument()
