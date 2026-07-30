# BH Asia 2026 NOC - AI-Powered SOC Platform Setup Guide

## Executive Summary

| Attribute | Value |
|-----------|-------|
| **Event** | Black Hat Asia 2026 NOC |
| **Duration** | 5 days event + 2 days buffer (7 days total) |
| **Region** | `ap-southeast-1` (Singapore) |
| **Data Volume** | ~50GB total (~10GB/day) |
| **Data Retention** | 7 days, then full deletion |
| **Data Sources** | Corelight (Zeek), Palo Alto, Partners |
| **Architecture** | EC2 + Docker (OpenSearch) |
| **Estimated Cost** | ~$25-35 for 7-day event |

---

## AWS Organization Structure (COMPLETED)

```
AWS Organization: <ORG-ID>
│
├── Management Account: <ACCOUNT-ID-MANAGEMENT> (Account Owner)
│   └── Role: Organization administration, billing
│
├── OU: Security (<OU-ID>)
│   └── bhasia-security (<ACCOUNT-ID-SECURITY>)
│       └── Role: Security tooling, audit logs
│
├── OU: Production (<OU-ID>)
│   └── bhasia-production (<ACCOUNT-ID-PRODUCTION>)
│       └── Role: NOC platform, data ingestion
│
├── OU: Development (<OU-ID>)
│   └── bhasia-development (<ACCOUNT-ID-DEVELOPMENT>)
│       └── Role: Testing, development
│
└── OU: Sandbox (<OU-ID>)
    └── (empty - for experimentation)
```

### Active Service Control Policies (SCPs)

| SCP | ID | Effect |
|-----|-----|--------|
| BHAsia-DenyRootUsage | <SCP-ID> | Blocks root account in member accounts |
| BHAsia-RequireMFAForSensitive | <SCP-ID> | MFA required for CloudTrail changes |
| BHAsia-DenyLeaveOrg | <SCP-ID> | Prevents accounts from leaving |
| BHAsia-RegionRestriction | <SCP-ID> | Only ap-southeast-1 + us-east-1 allowed |

### Alternate Contacts

| Type | Contact |
|------|---------|
| Billing | <BILLING-EMAIL> |
| Security | <SECURITY-EMAIL> |
| Operations | <OPS-EMAIL> |

### CloudTrail

- **Trail Name:** `bhasia-org-trail`
- **S3 Bucket:** `bhasia-cloudtrail-<ACCOUNT-ID-MANAGEMENT>`
- **Scope:** Organization-wide, multi-region
- **Log Validation:** Enabled

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        BH ASIA 2026 NOC - DATA PLATFORM                         │
│                           Region: ap-southeast-1                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  DATA SOURCES (External)                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                             │
│  │  Corelight  │  │  Palo Alto  │  │  Partners   │                             │
│  │  (Zeek JSON)│  │  (JSON)     │  │  (JSON)     │                             │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                             │
│         │                │                │                                      │
│         └────────────────┼────────────────┘                                      │
│                          │                                                       │
│                          ▼                                                       │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │                     INGESTION LAYER (EC2 t3.large)                        │  │
│  │                                                                           │  │
│  │   ┌─────────────────────────────────────────────────────────────────┐    │  │
│  │   │  Nginx (TLS Termination)                                        │    │  │
│  │   │  - SSL/TLS 1.3                                                  │    │  │
│  │   │  - Client certificate validation (optional)                     │    │  │
│  │   │  - Rate limiting                                                │    │  │
│  │   └─────────────────────────────────────────────────────────────────┘    │  │
│  │                          │                                                │  │
│  │                          ▼                                                │  │
│  │   ┌─────────────────────────────────────────────────────────────────┐    │  │
│  │   │  Ingestion API (Python FastAPI)                                 │    │  │
│  │   │  - API Key authentication per source                            │    │  │
│  │   │  - Input validation & sanitization                              │    │  │
│  │   │  - Source identification (corelight/paloalto/partner)          │    │  │
│  │   │  - Bulk insert batching                                         │    │  │
│  │   └─────────────────────────────────────────────────────────────────┘    │  │
│  │                          │                                                │  │
│  │         ┌────────────────┼────────────────┐                              │  │
│  │         ▼                                 ▼                              │  │
│  │   ┌───────────────┐              ┌───────────────┐                       │  │
│  │   │  S3 Backup    │              │  OpenSearch   │                       │  │
│  │   │  (Raw JSON)   │              │  (Docker)     │                       │  │
│  │   │               │              │               │                       │  │
│  │   │  - 7-day      │              │  - 50GB index │                       │  │
│  │   │    lifecycle  │              │  - Full-text  │                       │  │
│  │   │  - Audit/     │              │  - JSON native│                       │  │
│  │   │    recovery   │              │  - Port 9200  │                       │  │
│  │   └───────────────┘              └───────┬───────┘                       │  │
│  │                                          │                                │  │
│  └──────────────────────────────────────────┼────────────────────────────────┘  │
│                                             │                                    │
│  ┌──────────────────────────────────────────┼────────────────────────────────┐  │
│  │                     QUERY LAYER          │                                 │  │
│  │                                          ▼                                 │  │
│  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐              │  │
│  │   │  User       │───▶│  LLM Agent  │───▶│  OpenSearch     │              │  │
│  │   │  Question   │    │  (Python)   │    │  Query API      │              │  │
│  │   │             │    │             │    │                 │              │  │
│  │   │  "Show me   │    │  Translates │    │  Returns JSON   │              │  │
│  │   │   all SSH   │    │  to ES DSL  │    │  results        │              │  │
│  │   │   traffic"  │    │  query      │    │                 │              │  │
│  │   └─────────────┘    └─────────────┘    └─────────────────┘              │  │
│  │                                                                           │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
│                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## Data Platform Architecture (Option B: EC2 + OpenSearch Docker)

### Why This Architecture

| Factor | Decision | Rationale |
|--------|----------|-----------|
| **Cost** | EC2 + Docker | ~$25-35 vs $160+ for OpenSearch Serverless |
| **Complexity** | Single instance | 7-day event, no need for HA |
| **Data Volume** | 50GB | Fits comfortably in 100GB EBS |
| **Query Pattern** | LLM agents | OpenSearch DSL well-supported by models |
| **Retention** | 7 days | Simple deletion, no long-term storage |

### Infrastructure Components

#### Data Server (EC2 t3.large)

| Component | Specification |
|-----------|--------------|
| **Instance Type** | t3.large (2 vCPU, 8GB RAM) |
| **Storage** | 100GB gp3 EBS (encrypted) |
| **OS** | Amazon Linux 2023 |
| **Region** | ap-southeast-1 |
| **Cost** | ~$1.90/day |

#### Docker Containers

```yaml
# docker-compose.yml for data server
version: '3.8'

services:
  opensearch:
    image: opensearchproject/opensearch:2.11.0
    container_name: opensearch
    environment:
      - discovery.type=single-node
      - bootstrap.memory_lock=true
      - "OPENSEARCH_JAVA_OPTS=-Xms4g -Xmx4g"
      - plugins.security.disabled=true  # Internal only, TLS at nginx
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
    volumes:
      - opensearch-data:/usr/share/opensearch/data
    ports:
      - "127.0.0.1:9200:9200"
    restart: unless-stopped

  ingestion-api:
    build: ./ingestion-api
    container_name: ingestion-api
    environment:
      - OPENSEARCH_HOST=opensearch
      - OPENSEARCH_PORT=9200
      - API_KEYS_FILE=/run/secrets/api_keys
    volumes:
      - ./logs:/app/logs
    secrets:
      - api_keys
    ports:
      - "127.0.0.1:8000:8000"
    depends_on:
      - opensearch
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    container_name: nginx
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
    ports:
      - "443:443"
    depends_on:
      - ingestion-api
    restart: unless-stopped

volumes:
  opensearch-data:

secrets:
  api_keys:
    file: ./secrets/api_keys.json
```

---

## Ingestion API Design

### Endpoints

```
POST /v1/ingest/{source_type}
  - source_type: corelight | paloalto | partner-{name}
  - Headers:
      X-API-Key: <source-specific-key>
      Content-Type: application/json
  - Body: Single event or batch {"events": [...]}
  - Response: {"ingested": N, "errors": [...]}

GET /v1/health
  - Public health check
  - Response: {"status": "healthy", "opensearch": "connected"}

GET /v1/stats
  - Requires API key
  - Response: {"total_docs": N, "index_size_gb": N, "sources": {...}}
```

### Authentication

```python
# API Keys stored in /run/secrets/api_keys.json
{
    "sources": {
        "corelight": {
            "api_key": "bhasia-cl-XXXXXXXXXXXXXXXX",
            "allowed_ips": ["203.0.113.10", "203.0.113.11"],
            "rate_limit": 1000  # requests per minute
        },
        "paloalto": {
            "api_key": "bhasia-pa-XXXXXXXXXXXXXXXX",
            "allowed_ips": ["203.0.113.20"],
            "rate_limit": 500
        },
        "partner-cisco": {
            "api_key": "bhasia-cisco-XXXXXXXXXXXXXXXX",
            "allowed_ips": [],  # Any IP allowed
            "rate_limit": 200
        }
    }
}
```

### Ingestion API Implementation

```python
# ingestion-api/main.py
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from opensearchpy import OpenSearch
from datetime import datetime, timezone
import json
import hashlib
import logging

app = FastAPI(title="BH Asia NOC Data Ingestion API")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# OpenSearch client
os_client = OpenSearch(
    hosts=[{"host": "opensearch", "port": 9200}],
    http_compress=True,
    timeout=30
)

# Load API keys
with open("/run/secrets/api_keys.json") as f:
    API_KEYS = json.load(f)


class Event(BaseModel):
    """Single security event"""
    timestamp: Optional[str] = None
    data: Dict[str, Any]


class BatchEvents(BaseModel):
    """Batch of events"""
    events: List[Dict[str, Any]]


def validate_api_key(api_key: str, source_type: str, client_ip: str) -> bool:
    """Validate API key and IP restrictions"""
    if source_type not in API_KEYS["sources"]:
        return False

    source_config = API_KEYS["sources"][source_type]

    if source_config["api_key"] != api_key:
        return False

    allowed_ips = source_config.get("allowed_ips", [])
    if allowed_ips and client_ip not in allowed_ips:
        logger.warning(f"IP {client_ip} not allowed for source {source_type}")
        return False

    return True


def get_index_name(source_type: str) -> str:
    """Generate index name based on source and date"""
    date_str = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    return f"bhasia-{source_type}-{date_str}"


@app.post("/v1/ingest/{source_type}")
async def ingest_events(
    source_type: str,
    request: Request,
    x_api_key: str = Header(..., alias="X-API-Key")
):
    """Ingest security events from known sources"""

    client_ip = request.client.host

    # Validate authentication
    if not validate_api_key(x_api_key, source_type, client_ip):
        logger.warning(f"Authentication failed for {source_type} from {client_ip}")
        raise HTTPException(status_code=401, detail="Invalid API key or IP not allowed")

    # Parse request body
    body = await request.json()

    # Handle single event or batch
    if "events" in body:
        events = body["events"]
    else:
        events = [body]

    # Prepare bulk insert
    index_name = get_index_name(source_type)
    bulk_body = []

    for event in events:
        # Add metadata
        doc = {
            "_source_type": source_type,
            "_ingested_at": datetime.now(timezone.utc).isoformat(),
            "_client_ip": client_ip,
            **event
        }

        # Generate document ID from content hash
        doc_id = hashlib.sha256(
            json.dumps(event, sort_keys=True).encode()
        ).hexdigest()[:16]

        bulk_body.append({"index": {"_index": index_name, "_id": doc_id}})
        bulk_body.append(doc)

    # Execute bulk insert
    try:
        response = os_client.bulk(body=bulk_body, refresh=True)

        ingested = sum(1 for item in response["items"] if item["index"]["status"] in [200, 201])
        errors = [item["index"]["error"] for item in response["items"] if "error" in item["index"]]

        logger.info(f"Ingested {ingested}/{len(events)} events from {source_type}")

        return {
            "ingested": ingested,
            "total": len(events),
            "errors": errors[:10] if errors else []  # Limit error details
        }

    except Exception as e:
        logger.error(f"Bulk insert failed: {e}")
        raise HTTPException(status_code=500, detail="Ingestion failed")


@app.get("/v1/health")
async def health_check():
    """Public health check endpoint"""
    try:
        os_client.cluster.health()
        return {"status": "healthy", "opensearch": "connected"}
    except Exception:
        return {"status": "degraded", "opensearch": "disconnected"}


@app.get("/v1/stats")
async def get_stats(x_api_key: str = Header(..., alias="X-API-Key")):
    """Get ingestion statistics (requires any valid API key)"""

    # Validate any API key
    valid = any(
        config["api_key"] == x_api_key
        for config in API_KEYS["sources"].values()
    )
    if not valid:
        raise HTTPException(status_code=401, detail="Invalid API key")

    # Get index stats
    indices = os_client.cat.indices(index="bhasia-*", format="json")

    total_docs = sum(int(idx.get("docs.count", 0)) for idx in indices)
    total_size = sum(float(idx.get("store.size", "0kb").replace("kb", "").replace("mb", "000").replace("gb", "000000")) for idx in indices)

    return {
        "total_docs": total_docs,
        "total_size_mb": round(total_size / 1000, 2),
        "indices": [{"name": idx["index"], "docs": idx["docs.count"]} for idx in indices]
    }
```

---

## OpenSearch Index Configuration

### Index Template

```json
{
  "index_patterns": ["bhasia-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "refresh_interval": "5s",
      "index.mapping.total_fields.limit": 2000
    },
    "mappings": {
      "dynamic": true,
      "properties": {
        "_source_type": { "type": "keyword" },
        "_ingested_at": { "type": "date" },
        "_client_ip": { "type": "ip" },
        "timestamp": { "type": "date" },
        "ts": { "type": "date" },
        "@timestamp": { "type": "date" },
        "id.orig_h": { "type": "ip" },
        "id.orig_p": { "type": "integer" },
        "id.resp_h": { "type": "ip" },
        "id.resp_p": { "type": "integer" },
        "src_ip": { "type": "ip" },
        "dst_ip": { "type": "ip" },
        "src_port": { "type": "integer" },
        "dst_port": { "type": "integer" },
        "proto": { "type": "keyword" },
        "service": { "type": "keyword" },
        "action": { "type": "keyword" },
        "severity": { "type": "keyword" },
        "query": { "type": "text" },
        "user": { "type": "keyword" },
        "user_agent": { "type": "text" }
      }
    }
  }
}
```

### Sample Queries (for LLM Agents)

```python
# Example: Agent translates user question to OpenSearch DSL

# User: "Show me all SSH connections in the last hour"
query = {
    "query": {
        "bool": {
            "must": [
                {"term": {"id.resp_p": 22}},
                {"range": {"@timestamp": {"gte": "now-1h"}}}
            ]
        }
    },
    "size": 100
}

# User: "Find DNS queries to suspicious domains"
query = {
    "query": {
        "bool": {
            "must": [
                {"term": {"_source_type": "corelight"}},
                {"exists": {"field": "query"}}
            ],
            "should": [
                {"wildcard": {"query": "*.xyz"}},
                {"wildcard": {"query": "*.top"}},
                {"wildcard": {"query": "*.ru"}}
            ],
            "minimum_should_match": 1
        }
    }
}

# User: "What IPs have the most failed connections?"
query = {
    "size": 0,
    "query": {
        "term": {"conn_state": "REJ"}
    },
    "aggs": {
        "top_sources": {
            "terms": {
                "field": "id.orig_h",
                "size": 10
            }
        }
    }
}
```

---

## Cost Breakdown (7-Day Event)

| Resource | Specification | Daily Cost | 7-Day Cost |
|----------|--------------|------------|------------|
| EC2 t3.large | 2 vCPU, 8GB RAM | $1.90 | $13.30 |
| EBS gp3 100GB | Storage | $0.29 | $2.03 |
| Data Transfer IN | ~50GB total | $0.00 | $0.00 |
| S3 Backup | ~50GB | $0.04 | $0.28 |
| **Total** | | **$2.23** | **~$16** |

**Buffer for contingency:** ~$10-15

**Total estimated:** **$25-35**

---

## Security Controls

### Network Security

```
┌─────────────────────────────────────────────────────────┐
│                    Security Group                        │
├─────────────────────────────────────────────────────────┤
│  Inbound:                                                │
│    - 443/tcp from 0.0.0.0/0 (HTTPS ingestion)           │
│    - 22/tcp from YOUR_IP/32 (SSH admin)                 │
│                                                          │
│  Outbound:                                               │
│    - 443/tcp to 0.0.0.0/0 (AWS APIs, LLM)              │
│                                                          │
│  Internal (localhost only):                              │
│    - 9200/tcp OpenSearch                                │
│    - 8000/tcp Ingestion API                             │
└─────────────────────────────────────────────────────────┘
```

### Data Security

| Control | Implementation |
|---------|----------------|
| **Encryption at Rest** | EBS encryption (AWS managed key) |
| **Encryption in Transit** | TLS 1.3 via Nginx |
| **Authentication** | API Keys per source |
| **IP Restriction** | Optional allowlist per source |
| **Rate Limiting** | Nginx + per-source limits |
| **Audit Logging** | All requests logged |
| **Data Sanitization** | Pre-sanitized by sources |

### Data Retention & Deletion

```bash
# Automatic cleanup script (runs on Day 7)
#!/bin/bash
# delete-all-data.sh

# Stop services
docker-compose down

# Delete OpenSearch data
docker volume rm bhasia_opensearch-data

# Delete S3 backup
aws s3 rm s3://bhasia-data-backup-${ACCOUNT_ID}/ --recursive

# Delete the bucket
aws s3 rb s3://bhasia-data-backup-${ACCOUNT_ID}

# Terminate EC2 instance
aws ec2 terminate-instances --instance-ids ${INSTANCE_ID}

# Delete EBS snapshots
aws ec2 describe-snapshots --owner-ids self \
    --filters "Name=tag:Project,Values=BHAsia2026" \
    --query 'Snapshots[*].SnapshotId' --output text | \
    xargs -I {} aws ec2 delete-snapshot --snapshot-id {}

echo "All data deleted"
```

---

## Deployment Steps

### 1. Launch EC2 Instance

```bash
# Assume role into bhasia-production account
aws sts assume-role \
    --role-arn arn:aws:iam::<ACCOUNT-ID-PRODUCTION>:role/OrganizationAccountAccessRole \
    --role-session-name DataPlatformSetup > /tmp/creds.json

export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId' /tmp/creds.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' /tmp/creds.json)
export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken' /tmp/creds.json)

# Create key pair
aws ec2 create-key-pair \
    --key-name bhasia-data-server \
    --query 'KeyMaterial' \
    --output text \
    --region ap-southeast-1 > bhasia-data-server.pem
chmod 400 bhasia-data-server.pem

# Create security group
SG_ID=$(aws ec2 create-security-group \
    --group-name bhasia-data-sg \
    --description "BH Asia Data Server" \
    --region ap-southeast-1 \
    --query 'GroupId' --output text)

# Add rules
aws ec2 authorize-security-group-ingress \
    --group-id $SG_ID \
    --protocol tcp --port 443 --cidr 0.0.0.0/0 \
    --region ap-southeast-1

aws ec2 authorize-security-group-ingress \
    --group-id $SG_ID \
    --protocol tcp --port 22 --cidr YOUR_IP/32 \
    --region ap-southeast-1

# Launch instance
INSTANCE_ID=$(aws ec2 run-instances \
    --image-id ami-0df7a207adb9748c7 \
    --instance-type t3.large \
    --key-name bhasia-data-server \
    --security-group-ids $SG_ID \
    --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":100,"VolumeType":"gp3","Encrypted":true}}]' \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=bhasia-data-server},{Key=Project,Value=BHAsia2026}]' \
    --region ap-southeast-1 \
    --query 'Instances[0].InstanceId' --output text)

echo "Instance ID: $INSTANCE_ID"

# Wait for instance
aws ec2 wait instance-running --instance-ids $INSTANCE_ID --region ap-southeast-1

# Get public IP
PUBLIC_IP=$(aws ec2 describe-instances \
    --instance-ids $INSTANCE_ID \
    --query 'Reservations[0].Instances[0].PublicIpAddress' \
    --output text --region ap-southeast-1)

echo "Public IP: $PUBLIC_IP"
```

### 2. Configure Instance

```bash
# SSH into instance
ssh -i bhasia-data-server.pem ec2-user@$PUBLIC_IP

# Add admin SSH keys (required on all instances)
cat >> ~/.ssh/authorized_keys << 'EOF'
ssh-ed25519 <REDACTED> admin@workstation
ssh-ed25519 <REDACTED> blackhat
EOF

# Install Docker
sudo yum update -y
sudo yum install -y docker git
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker ec2-user

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Increase vm.max_map_count for OpenSearch
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -w vm.max_map_count=262144

# Create application directory
sudo mkdir -p /opt/bhasia
sudo chown ec2-user:ec2-user /opt/bhasia
cd /opt/bhasia

# Clone or copy application files
# (docker-compose.yml, ingestion-api/, nginx/, secrets/)

# Start services
docker-compose up -d

# Verify
docker-compose ps
curl -k https://localhost/v1/health
```

### 3. Configure SSL Certificate

```bash
# Option A: Self-signed (for testing)
openssl req -x509 -nodes -days 7 \
    -newkey rsa:2048 \
    -keyout /opt/bhasia/nginx/ssl/server.key \
    -out /opt/bhasia/nginx/ssl/server.crt \
    -subj "/CN=bhasia-data.blackhat.com"

# Option B: Let's Encrypt (if you have a domain)
sudo yum install -y certbot
sudo certbot certonly --standalone -d your-domain.com
```

### 4. Generate API Keys

```bash
# Generate secure API keys for each source
cat > /opt/bhasia/secrets/api_keys.json << 'EOF'
{
    "sources": {
        "corelight": {
            "api_key": "bhasia-cl-$(openssl rand -hex 24)",
            "allowed_ips": [],
            "rate_limit": 1000
        },
        "paloalto": {
            "api_key": "bhasia-pa-$(openssl rand -hex 24)",
            "allowed_ips": [],
            "rate_limit": 500
        },
        "partner-default": {
            "api_key": "bhasia-ptr-$(openssl rand -hex 24)",
            "allowed_ips": [],
            "rate_limit": 200
        }
    }
}
EOF

# Restart to pick up new keys
docker-compose restart ingestion-api
```

### 5. Test Ingestion

```bash
# Test health endpoint
curl -k https://$PUBLIC_IP/v1/health

# Test ingestion (replace API_KEY)
curl -k -X POST https://$PUBLIC_IP/v1/ingest/corelight \
    -H "Content-Type: application/json" \
    -H "X-API-Key: bhasia-cl-XXXXX" \
    -d '{
        "ts": "2026-04-20T10:00:00Z",
        "uid": "CYT2Zp3fHx5tqRiPM4",
        "id.orig_h": "192.168.1.100",
        "id.orig_p": 49234,
        "id.resp_h": "93.184.216.34",
        "id.resp_p": 443,
        "proto": "tcp",
        "service": "ssl"
    }'

# Verify in OpenSearch
curl -s http://localhost:9200/bhasia-corelight-*/_search | jq .
```

---

## LLM Agent Integration

### Query Interface

```python
# agent_query.py - Used by LLM agents to query data
from opensearchpy import OpenSearch
from typing import Dict, Any, List

class DataQueryAgent:
    """Interface for LLM agents to query NOC data"""

    def __init__(self, opensearch_host: str = "localhost"):
        self.client = OpenSearch(
            hosts=[{"host": opensearch_host, "port": 9200}]
        )

    def search(self, query: Dict[str, Any], index: str = "bhasia-*") -> List[Dict]:
        """Execute OpenSearch query and return results"""
        response = self.client.search(index=index, body=query)
        return response["hits"]["hits"]

    def natural_language_query(self, question: str) -> str:
        """
        Convert natural language to OpenSearch DSL
        This method would call the LLM to generate the query
        """
        # LLM generates query based on question
        # Example prompt: "Convert this question to OpenSearch DSL: {question}"
        pass

    def get_connection_summary(self, time_range: str = "1h") -> Dict:
        """Get summary of connections in time range"""
        query = {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
            "aggs": {
                "by_source": {"terms": {"field": "_source_type", "size": 10}},
                "by_protocol": {"terms": {"field": "proto", "size": 10}},
                "top_talkers": {"terms": {"field": "id.orig_h", "size": 10}}
            }
        }
        return self.client.search(index="bhasia-*", body=query)

    def find_suspicious_activity(self) -> List[Dict]:
        """Find potentially suspicious network activity"""
        query = {
            "query": {
                "bool": {
                    "should": [
                        # Failed connections
                        {"term": {"conn_state": "REJ"}},
                        # Unusual ports
                        {"range": {"id.resp_p": {"gt": 49151}}},
                        # Known bad TLDs in DNS
                        {"wildcard": {"query": "*.xyz"}},
                        {"wildcard": {"query": "*.top"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "size": 100,
            "sort": [{"@timestamp": "desc"}]
        }
        return self.search(query)
```

---

## Monitoring & Alerts

### CloudWatch Metrics

```bash
# Create CloudWatch alarm for disk usage
aws cloudwatch put-metric-alarm \
    --alarm-name bhasia-disk-high \
    --metric-name DiskSpaceUtilization \
    --namespace CWAgent \
    --statistic Average \
    --period 300 \
    --threshold 80 \
    --comparison-operator GreaterThanThreshold \
    --evaluation-periods 2 \
    --alarm-actions arn:aws:sns:ap-southeast-1:<ACCOUNT-ID-PRODUCTION>:bhasia-alerts \
    --dimensions Name=InstanceId,Value=$INSTANCE_ID \
    --region ap-southeast-1
```

### Health Check Script

```bash
#!/bin/bash
# health-check.sh - Run periodically via cron

API_URL="https://localhost/v1/health"
SLACK_WEBHOOK="https://hooks.slack.com/services/XXX"

response=$(curl -sk $API_URL)
status=$(echo $response | jq -r '.status')

if [ "$status" != "healthy" ]; then
    curl -X POST $SLACK_WEBHOOK \
        -H 'Content-type: application/json' \
        -d "{\"text\":\"BH Asia Data Platform UNHEALTHY: $response\"}"
fi
```

---

## Checklist

### Pre-Event Setup
- [ ] EC2 instance launched in ap-southeast-1
- [ ] Docker and Docker Compose installed
- [ ] OpenSearch container running
- [ ] Ingestion API container running
- [ ] Nginx with TLS configured
- [ ] API keys generated and distributed to sources
- [ ] Health check verified
- [ ] CloudWatch alarms configured
- [ ] S3 backup bucket created

### During Event
- [ ] Monitor disk usage (stay under 80%)
- [ ] Monitor ingestion rate
- [ ] Check for errors in logs
- [ ] Verify LLM agent queries working

### Post-Event (Day 7)
- [ ] Run delete-all-data.sh
- [ ] Verify all data deleted
- [ ] Terminate EC2 instance
- [ ] Delete S3 bucket
- [ ] Delete EBS snapshots
- [ ] Confirm CloudTrail shows deletion

---

## Troubleshooting

### OpenSearch Won't Start
```bash
# Check vm.max_map_count
sysctl vm.max_map_count
# Should be 262144

# Check logs
docker logs opensearch
```

### Ingestion Failing
```bash
# Check API logs
docker logs ingestion-api

# Test OpenSearch directly
curl http://localhost:9200/_cluster/health

# Check index status
curl http://localhost:9200/_cat/indices?v
```

### Disk Full
```bash
# Check disk usage
df -h

# Delete old indices (if needed)
curl -X DELETE http://localhost:9200/bhasia-corelight-2026.04.15

# Force merge to reclaim space
curl -X POST http://localhost:9200/bhasia-*/_forcemerge?max_num_segments=1
```

---

*Last Updated: 2026-04-17*
*Document Version: 2.0*
