# BH Asia 2026 NOC — Data Ingestion API Reference

**For partner use only. Keep your API key confidential.**

---

## Overview

The BH Asia 2026 NOC platform accepts real-time security telemetry from conference network data sources. All events are ingested via a simple HTTPS REST API, stored in OpenSearch, and made available to the AI analyst agents running on the platform.

| Attribute | Value |
|-----------|-------|
| **Endpoint Base URL** | `https://<EC2-PUBLIC-IP>` |
| **Protocol** | HTTPS (TLS 1.2+) |
| **Authentication** | API Key per source (`X-API-Key` header) |
| **Data Format** | JSON (single event or batch) |
| **SSL Certificate** | Self-signed — use `-k` / `--insecure` or import the cert |

---

## Authentication

Each data source is issued a unique API key. Include it in every request:

```
X-API-Key: bhasia-<source>-<secret>
```

Contact the NOC team to receive your API key. Keys are scoped per source type — a Corelight key cannot post to the PaloAlto endpoint and vice versa.

---

## Endpoints

### `POST /v1/ingest/{source_type}`

Ingest one or more security events.

**Path parameters**

| Parameter | Values | Description |
|-----------|--------|-------------|
| `source_type` | `corelight`, `paloalto`, `partner-default` | Identifies your data source |

**Headers**

| Header | Required | Description |
|--------|----------|-------------|
| `Content-Type` | Yes | `application/json` |
| `X-API-Key` | Yes | Your source API key |

**Request body**

Send a single event object, or a batch:

```json
// Single event
{ "field1": "value1", "field2": "value2", ... }

// Batch of events
{ "events": [ {...}, {...}, {...} ] }
```

**Response**

```json
{
  "ingested": 3,
  "total": 3,
  "errors": []
}
```

| Field | Type | Description |
|-------|------|-------------|
| `ingested` | integer | Number of events successfully stored |
| `total` | integer | Number of events in the request |
| `errors` | array | Any per-event errors (empty on full success) |

**HTTP status codes**

| Code | Meaning |
|------|---------|
| `200` | Success |
| `401` | Invalid or missing API key |
| `500` | Server-side ingestion failure |

---

### `GET /v1/health`

Public health check. No authentication required.

```json
{
  "status": "healthy",
  "opensearch": "green",
  "timestamp": "2026-04-19T02:35:45.984028+00:00"
}
```

---

### `GET /v1/stats`

Returns ingestion statistics. Requires a valid API key.

**Headers:** `X-API-Key: <your-key>`

```json
{
  "total_docs": 14523,
  "indices": [
    { "name": "bhasia-corelight-2026.04.19", "docs": "9041" },
    { "name": "bhasia-paloalto-2026.04.19", "docs": "5482" }
  ]
}
```

---

## Source-Specific Field Guidance

While the API accepts arbitrary JSON, the following fields are indexed with specific types and should be used consistently for best query performance.

### Corelight / Zeek

| Field | Type | Example |
|-------|------|---------|
| `ts` | datetime (ISO 8601) | `"2026-04-19T10:00:00Z"` |
| `@timestamp` | datetime (ISO 8601) | `"2026-04-19T10:00:00Z"` |
| `uid` | string | `"CYT2Zp3fHx5tqRiPM4"` |
| `id.orig_h` | IP address | `"192.168.1.100"` |
| `id.orig_p` | integer | `49234` |
| `id.resp_h` | IP address | `"93.184.216.34"` |
| `id.resp_p` | integer | `443` |
| `proto` | keyword | `"tcp"`, `"udp"` |
| `service` | keyword | `"ssl"`, `"dns"`, `"http"` |
| `conn_state` | keyword | `"S1"`, `"SF"`, `"REJ"`, `"S0"` |
| `query` | text | DNS query name |

### Palo Alto

| Field | Type | Example |
|-------|------|---------|
| `@timestamp` | datetime (ISO 8601) | `"2026-04-19T10:00:00Z"` |
| `src_ip` | IP address | `"10.0.1.50"` |
| `dst_ip` | IP address | `"8.8.8.8"` |
| `src_port` | integer | `54321` |
| `dst_port` | integer | `53` |
| `proto` | keyword | `"tcp"`, `"udp"` |
| `action` | keyword | `"allow"`, `"deny"`, `"drop"` |
| `severity` | keyword | `"critical"`, `"high"`, `"medium"`, `"low"`, `"informational"` |
| `user` | keyword | Username if available |

### Partners / Generic

Any JSON fields are accepted and stored. Include `@timestamp` (ISO 8601) for time-based querying.

---

## Code Examples

### curl

```bash
# Single event — Corelight
curl -k -X POST https://<EC2-PUBLIC-IP>/v1/ingest/corelight \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "@timestamp": "2026-04-19T10:00:00Z",
    "uid": "CYT2Zp3fHx5tqRiPM4",
    "id.orig_h": "192.168.1.100",
    "id.orig_p": 49234,
    "id.resp_h": "93.184.216.34",
    "id.resp_p": 443,
    "proto": "tcp",
    "service": "ssl",
    "conn_state": "S1"
  }'

# Batch of events — PaloAlto
curl -k -X POST https://<EC2-PUBLIC-IP>/v1/ingest/paloalto \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "events": [
      {
        "@timestamp": "2026-04-19T10:00:01Z",
        "src_ip": "10.0.1.50",
        "dst_ip": "8.8.8.8",
        "dst_port": 53,
        "proto": "udp",
        "action": "allow"
      },
      {
        "@timestamp": "2026-04-19T10:00:02Z",
        "src_ip": "10.0.2.30",
        "dst_ip": "185.220.101.47",
        "dst_port": 9001,
        "proto": "tcp",
        "action": "deny",
        "severity": "high"
      }
    ]
  }'

# Health check (no auth required)
curl -k https://<EC2-PUBLIC-IP>/v1/health

# Statistics
curl -k https://<EC2-PUBLIC-IP>/v1/stats \
  -H "X-API-Key: YOUR_API_KEY"
```

### Python

```python
import httpx

API_URL = "https://<EC2-PUBLIC-IP>"
API_KEY = "YOUR_API_KEY"
SOURCE = "corelight"  # or "paloalto", "partner-default"

client = httpx.Client(verify=False, headers={"X-API-Key": API_KEY})

# Send a single event
event = {
    "@timestamp": "2026-04-19T10:00:00Z",
    "id.orig_h": "192.168.1.100",
    "id.orig_p": 49234,
    "id.resp_h": "1.2.3.4",
    "id.resp_p": 443,
    "proto": "tcp",
    "service": "ssl",
}
resp = client.post(f"{API_URL}/v1/ingest/{SOURCE}", json=event)
print(resp.json())  # {"ingested": 1, "total": 1, "errors": []}

# Send a batch
batch = {"events": [event1, event2, event3]}
resp = client.post(f"{API_URL}/v1/ingest/{SOURCE}", json=batch)
print(resp.json())  # {"ingested": 3, "total": 3, "errors": []}
```

### Python — Zeek/Corelight log streaming

```python
import httpx
import json
import time

API_URL = "https://<EC2-PUBLIC-IP>"
API_KEY = "YOUR_CORELIGHT_API_KEY"
BATCH_SIZE = 100
FLUSH_INTERVAL = 5  # seconds

client = httpx.Client(verify=False, headers={"X-API-Key": API_KEY})
buffer = []
last_flush = time.time()


def flush(batch):
    if not batch:
        return
    resp = client.post(f"{API_URL}/v1/ingest/corelight", json={"events": batch})
    data = resp.json()
    print(f"Flushed {data['ingested']}/{data['total']} events")


# Stream from Zeek log file
with open("/path/to/zeek/conn.log") as f:
    for line in f:
        if line.startswith("#"):
            continue
        event = json.loads(line)
        buffer.append(event)

        if len(buffer) >= BATCH_SIZE or (time.time() - last_flush) > FLUSH_INTERVAL:
            flush(buffer)
            buffer.clear()
            last_flush = time.time()

    flush(buffer)  # Flush remainder
```

### JavaScript / Node.js

```javascript
const https = require('https');
const axios = require('axios');

const client = axios.create({
  baseURL: 'https://<EC2-PUBLIC-IP>',
  httpsAgent: new https.Agent({ rejectUnauthorized: false }),
  headers: { 'X-API-Key': 'YOUR_API_KEY' }
});

// Send single event
await client.post('/v1/ingest/corelight', {
  '@timestamp': new Date().toISOString(),
  'id.orig_h': '192.168.1.1',
  'id.resp_h': '1.2.3.4',
  'id.resp_p': 443,
  proto: 'tcp',
  service: 'ssl'
});

// Batch send
await client.post('/v1/ingest/paloalto', {
  events: events.map(e => ({ ...e, '@timestamp': new Date().toISOString() }))
});
```

---

## Deduplication

Events are deduplicated by content hash. Sending the same event payload twice will result in only one document stored. This is safe for retry logic — retrying a failed batch will not create duplicates.

---

## Rate Limits

| Source | Requests/minute |
|--------|----------------|
| Corelight | 1,000 |
| PaloAlto | 500 |
| Partners | 200 |

Exceeding the rate limit returns HTTP `429 Too Many Requests`. Implement exponential backoff on 429 responses.

---

## Data Retention

All ingested data is retained for **7 days** from the end of the event, then permanently deleted. No data leaves the Singapore AWS region (`ap-southeast-1`).

---

## SSL Certificate

The server uses a self-signed certificate. To avoid TLS errors without disabling verification, import the certificate:

```bash
# Download the certificate
openssl s_client -connect <EC2-PUBLIC-IP>:443 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM > bhasia-noc.crt

# Use with curl
curl --cacert bhasia-noc.crt https://<EC2-PUBLIC-IP>/v1/health

# Use with Python httpx/requests
client = httpx.Client(verify="bhasia-noc.crt")
```

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `401 Unauthorized` | Wrong or missing API key | Check `X-API-Key` header value |
| `SSL certificate error` | Self-signed cert | Use `-k` flag or import cert (see above) |
| `502 Bad Gateway` | Service restarting | Retry after 30 seconds |
| `500` on ingest | Malformed JSON or field type mismatch | Validate JSON; check IP fields are strings |
| Low `ingested` count | Duplicate events | Normal — deduplication is active |

---

## Contact

NOC operations: **<SECURITY-EMAIL>**

*Document version: 1.0 — 2026-04-19*
