# audit-monitor

Local-only live view of BHNOCgentic agent spans.

Polls the S3 trace archive at `s3://blackhat-pope-dev-logs/bh-asia-26/aing-trace/`
every 2 seconds, parses the gzipped NDJSON spans, and streams them over
Server-Sent Events to a browser UI that renders one swim-lane per agent.

## Run

```bash
# From repo root:
python3 -m venv tools/audit-monitor/.venv
source tools/audit-monitor/.venv/bin/activate
pip install -r tools/audit-monitor/requirements.txt

# AWS creds must be available via env or ~/.aws/credentials
export AWS_PROFILE=bhasia-deploy   # or AWS_ACCESS_KEY_ID / SECRET_ACCESS_KEY

python tools/audit-monitor/app.py
```

The browser will open at `http://localhost:8787`.

## Env vars

| var | default | meaning |
|---|---|---|
| `AUDIT_BUCKET` | `blackhat-pope-dev-logs` | S3 bucket |
| `AUDIT_PREFIX` | `bh-asia-26/aing-trace` | Key prefix for span objects |
| `AUDIT_REGION` | `us-west-2` | bucket region |
| `AUDIT_PORT` | `8787` | local HTTP port |
| `AUDIT_POLL_S` | `2` | S3 poll cadence (seconds) |
| `AUDIT_LOOKBACK` | `300` | initial history to pull (seconds) |

## What you see

- One swim-lane per service: **orchestrator, threat-hunter, alert-triage, athena-hunter, thousandeyes-analyst**.
- Spans appear newest-first, color-coded by kind (LLM=yellow, athena=purple, agent=cyan, tool=orange, http=green).
- Click any card for full attributes — prompt/completion text is surfaced in a **LLM / GenAI** section when present.
- Filter bar toggles per-kind visibility and a PAUSE checkbox.
- Re-connects automatically if the SSE stream drops.

## Data path

```
agents → OTel → S3SpanExporter (gzip NDJSON)
                    ↓
        s3://.../bh-asia-26/aing-trace/service=<svc>/dt=/hour=/file.jsonl.gz
                    ↓
        audit-monitor poll loop (boto3 list+get_object)
                    ↓
        SSE /api/stream → browser swim-lanes
```
