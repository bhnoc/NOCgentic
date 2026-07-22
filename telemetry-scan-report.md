# Library Usage Report

Usage Report - **Source:** Filesystem Scan

- `Date`: 2026-06-04
- `Languages`: python, javascript
- `Libraries`: all (71)

| Repos Scanned | 1 |
|------|----------|

### By Category

| Category | Repos | Findings |
|------|----------|----------|
| Observability & Telemetry | 1 | 25 |
| LLM & Agent Frameworks | 1 | 10 |
| LLM Provider SDKs | 1 | 5 |
| Vector Databases & RAG | 1 | 1 |

## BHNOCgentic Overview

| BHNOCgentic with Observability & Telemetry | 25 |
|------|----------|
| BHNOCgentic with LLM & Agent Frameworks | 10 |
| BHNOCgentic with LLM Provider SDKs | 5 |
| BHNOCgentic with Vector Databases & RAG | 1 |

## Detailed Findings

### opentelemetry

- `opentelemetry` (25 matches)
  - Direct dependencies: 5
  - Import statements: 14
  - Env var references: 6

##### Package: agents/shared

###### Direct Dependencies (5)

- `agents/shared/requirements.txt:4`: `opentelemetry-api>=1.25.0`
- `agents/shared/requirements.txt:5`: `opentelemetry-sdk>=1.25.0`
- `agents/shared/requirements.txt:6`: `opentelemetry-exporter-otlp-proto-http>=1.25.0`
- `agents/shared/requirements.txt:7`: `opentelemetry-instrumentation-fastapi>=0.46b0`
- `agents/shared/requirements.txt:8`: `opentelemetry-instrumentation-httpx>=0.46b0`

| Direct Dependencies | 5 |
|------|----------|

###### Lock Dependencies (0)

| Lock Dependencies | 0 |
|------|----------|

###### Import Statements (14)

- `agents/shared/telemetry.py:82`: `from opentelemetry import trace, metrics`
- `agents/shared/telemetry.py:83`: `from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter`
- `agents/shared/telemetry.py:84`: `from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter`
- `agents/shared/telemetry.py:85`: `from opentelemetry.sdk.resources import Resource`
- `agents/shared/telemetry.py:86`: `from opentelemetry.sdk.trace import TracerProvider`
- `agents/shared/telemetry.py:87`: `from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor, ConsoleSpanExporter`
- `agents/shared/telemetry.py:92`: `from opentelemetry.sdk.metrics import MeterProvider`
- `agents/shared/telemetry.py:93`: `from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader`
- `agents/shared/telemetry.py:103`: `from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased`
- `agents/shared/telemetry.py:235`: `from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor`
- `agents/shared/telemetry.py:255`: `from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor`
- `agents/shared/telemetry.py:272`: `from opentelemetry.propagate import inject`
- `agents/shared/s3_span_exporter.py:30`: `from opentelemetry.sdk.trace import ReadableSpan`
- `agents/shared/s3_span_exporter.py:31`: `from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult`

| Import Statements | 14 |
|------|----------|

###### Env Var References (6)

- `agents/shared/telemetry.py:59`: `OTEL_ENABLED`
- `agents/shared/telemetry.py:65`: `OTEL_EXPORTER_OTLP_ENDPOINT`
- `agents/shared/telemetry.py:67`: `OTEL_EXPORTER_OTLP_API_KEY`
- `agents/shared/telemetry.py:68`: `OTEL_SERVICE_NAME`
- `agents/shared/telemetry.py:69`: `OTEL_SAMPLE_RATE`
- `agents/shared/telemetry.py:70`: `OTEL_METRICS_INTERVAL_MS`
- `agents/shared/telemetry.py:71`: `OTEL_LOG_LEVEL`
- `agents/shared/telemetry.py:73`: `OTEL_CONSOLE_TRACES`
- `.env:24`: `OTEL_EXPORTER_OTLP_ENDPOINT`
- `.env:25`: `OTEL_EXPORTER_OTLP_API_KEY`
- `.env:26`: `OTEL_ENABLED`
- `.env.s3:20`: `OTEL_EXPORTER_OTLP_ENDPOINT`
- `.env.s3:21`: `OTEL_EXPORTER_OTLP_API_KEY`
- `.env.s3:22`: `OTEL_ENABLED`
- `docker-compose.agents.yml:20`: `OTEL_EXPORTER_OTLP_ENDPOINT`
- `docker-compose.agents.yml:21`: `OTEL_EXPORTER_OTLP_API_KEY`
- `docker-compose.agents.yml:22`: `OTEL_ENABLED`
- `docker-compose.agents.yml:23`: `OTEL_SERVICE_NAME`

| Env Var References | 6 |
|------|----------|

### langchain

- `langchain` (10 matches)
  - Direct dependencies: 4
  - Import statements: 3
  - Env var references: 3

##### Package: agents/shared

###### Direct Dependencies (4)

- `agents/shared/requirements.txt:9`: `langchain-core>=0.3.0`
- `agents/shared/requirements.txt:10`: `langchain-google-genai>=2.0.0`
- `agents/shared/requirements.txt:11`: `langchain-openai>=0.2.0`
- `agents/shared/requirements.txt:12`: `langsmith[otel]>=0.3.18`

| Direct Dependencies | 4 |
|------|----------|

###### Lock Dependencies (0)

| Lock Dependencies | 0 |
|------|----------|

###### Import Statements (3)

- `agents/shared/llm_client.py:157`: `from langchain_google_genai import ChatGoogleGenerativeAI`
- `agents/shared/llm_client.py:180`: `from langchain_openai import ChatOpenAI`
- `agents/shared/llm_client.py:233`: `from langchain_core.messages import SystemMessage, HumanMessage`

| Import Statements | 3 |
|------|----------|

###### Env Var References (3)

- `agents/shared/telemetry.py:155`: `LANGSMITH_TRACING`
- `agents/shared/telemetry.py:156`: `LANGSMITH_OTEL_ENABLED`
- `agents/shared/telemetry.py:158`: `LANGCHAIN_TRACING_V2`

| Env Var References | 3 |
|------|----------|

### gemini

- `gemini` (3 matches)
  - Direct dependencies: 0
  - Import statements: 0
  - Env var references: 3

##### Package: agents/shared

###### Direct Dependencies (0)

| Direct Dependencies | 0 |
|------|----------|

###### Lock Dependencies (0)

| Lock Dependencies | 0 |
|------|----------|

###### Import Statements (0)

| Import Statements | 0 |
|------|----------|

###### Env Var References (3)

- `.env:3`: `GEMINI_API_KEY`
- `.env.s3:3`: `GEMINI_API_KEY`
- `.env.example:3`: `GEMINI_API_KEY`

| Env Var References | 3 |
|------|----------|

### openai

- `openai` (2 matches)
  - Direct dependencies: 1
  - Import statements: 1
  - Env var references: 0

##### Package: agents/shared

###### Direct Dependencies (1)

- `agents/shared/requirements.txt:11`: `langchain-openai>=0.2.0`

| Direct Dependencies | 1 |
|------|----------|

###### Lock Dependencies (0)

| Lock Dependencies | 0 |
|------|----------|

###### Import Statements (1)

- `agents/shared/llm_client.py:180`: `from langchain_openai import ChatOpenAI`

| Import Statements | 1 |
|------|----------|

###### Env Var References (0)

| Env Var References | 0 |
|------|----------|

### mcp

- `mcp` (1 matches)
  - Direct dependencies: 1
  - Import statements: 0
  - Env var references: 0

##### Package: agents/thousandeyes-analyst

###### Direct Dependencies (1)

- `agents/thousandeyes-analyst/requirements.txt:5`: `mcp>=1.0.0`

| Direct Dependencies | 1 |
|------|----------|

###### Lock Dependencies (0)

| Lock Dependencies | 0 |
|------|----------|

###### Import Statements (0)

| Import Statements | 0 |
|------|----------|

###### Env Var References (0)

| Env Var References | 0 |
|------|----------|

### opensearch

- `opensearch` (1 matches)
  - Direct dependencies: 0
  - Import statements: 0
  - Env var references: 1

##### Package: packages/shared

###### Direct Dependencies (0)

| Direct Dependencies | 0 |
|------|----------|

###### Lock Dependencies (0)

| Lock Dependencies | 0 |
|------|----------|

###### Import Statements (0)

| Import Statements | 0 |
|------|----------|

###### Env Var References (1)

- `.env:5`: `OPENSEARCH_API_URL`
- `.env:9`: `OPENSEARCH_INTERNAL_URL`
- `.env.example:6`: `OPENSEARCH_API_URL`
- `.env.example:7`: `OPENSEARCH_API_KEY`

| Env Var References | 1 |
|------|----------|

Total findings: 41
