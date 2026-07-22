# BlackHat Asia 2026 - Athena Log Query Implementation Guide

## Overview

This document provides everything needed to build an application that queries Corelight network logs stored in AWS Athena. The data is pre-optimized in Parquet format for fast queries (sub-second for most operations).

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Corelight      │────▶│  S3 (Raw Logs)  │────▶│  S3 (Parquet)   │
│  Sensor         │     │  TSV/Gzip       │     │  Optimized      │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                                                        ▼
                                                ┌─────────────────┐
                                                │  AWS Athena     │
                                                │  (Query Engine) │
                                                └─────────────────┘
                                                        │
                                                        ▼
                                                ┌─────────────────┐
                                                │  Your App/LLM   │
                                                └─────────────────┘
```

---

## AWS Configuration

### Account & Region
- **AWS Account ID:** <ACCOUNT-ID>
- **Region:** us-west-2 (Oregon)
- **AWS Profile:** VirtualPOC-admins (for CLI access)

### Athena Configuration
- **Workgroup:** `blackhat-pope-dev`
- **Database:** `blackhat_pope_logs`
- **Results Bucket:** `s3://blackhat-pope-dev-athena-results/`

### S3 Buckets
| Bucket | Purpose |
|--------|---------|
| `blackhat-pope-dev-logs` | Raw Corelight logs (TSV/gzip) |
| `blackhat-pope-dev-parquet` | Optimized Parquet tables |
| `blackhat-pope-dev-athena-results` | Athena query results |

---

## IAM Permissions Required

Any application querying Athena needs these permissions. The EC2 instance `<INSTANCE-ID>` (AING) already has these via role `blackhat-pope-dev-ec2-role`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AthenaAccess",
      "Effect": "Allow",
      "Action": [
        "athena:StartQueryExecution",
        "athena:StopQueryExecution",
        "athena:GetQueryExecution",
        "athena:GetQueryResults",
        "athena:GetWorkGroup",
        "athena:ListQueryExecutions"
      ],
      "Resource": [
        "arn:aws:athena:us-west-2:<ACCOUNT-ID>:workgroup/blackhat-pope-dev"
      ]
    },
    {
      "Sid": "GlueAccess",
      "Effect": "Allow",
      "Action": [
        "glue:GetDatabase",
        "glue:GetDatabases",
        "glue:GetTable",
        "glue:GetTables",
        "glue:GetPartition",
        "glue:GetPartitions"
      ],
      "Resource": [
        "arn:aws:glue:us-west-2:<ACCOUNT-ID>:catalog",
        "arn:aws:glue:us-west-2:<ACCOUNT-ID>:database/blackhat_pope_logs",
        "arn:aws:glue:us-west-2:<ACCOUNT-ID>:table/blackhat_pope_logs/*"
      ]
    },
    {
      "Sid": "S3ReadAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::blackhat-pope-dev-logs",
        "arn:aws:s3:::blackhat-pope-dev-logs/*",
        "arn:aws:s3:::blackhat-pope-dev-parquet",
        "arn:aws:s3:::blackhat-pope-dev-parquet/*"
      ]
    },
    {
      "Sid": "S3ResultsAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket",
        "s3:GetBucketLocation"
      ],
      "Resource": [
        "arn:aws:s3:::blackhat-pope-dev-athena-results",
        "arn:aws:s3:::blackhat-pope-dev-athena-results/*"
      ]
    }
  ]
}
```

---

## Available Tables

All tables use date partitioning (`dt` column) in format `YYYY-MM-DD`. **Always include `WHERE dt='YYYY-MM-DD'`** for fast queries.

### Core Network Logs

| Table | Description | Key Fields |
|-------|-------------|------------|
| `conn` | All network connections | `uid`, `orig_h`, `resp_h`, `proto`, `service`, `duration`, `orig_bytes`, `resp_bytes` |
| `dns` | DNS queries/responses | `uid`, `query`, `qtype_name`, `rcode_name`, `answers`, `icann_domain` |
| `http` | HTTP requests | `uid`, `method`, `host`, `uri`, `user_agent`, `status_code` |
| `ssl` | TLS handshakes | `uid`, `server_name`, `version`, `cipher`, `ja3`, `ja3s`, `subject`, `issuer` |
| `ssh` | SSH sessions | `uid`, `version`, `auth_success`, `client`, `server`, `cipher_alg` |
| `files` | File transfers | `fuid`, `uid`, `mime_type`, `filename`, `md5`, `sha1`, `sha256`, `seen_bytes` |

### Authentication & Identity

| Table | Description | Key Fields |
|-------|-------------|------------|
| `dhcp` | DHCP leases | `mac`, `host_name`, `assigned_addr`, `lease_time` |
| `kerberos` | Kerberos auth | `uid`, `request_type`, `client`, `service`, `success`, `error_msg` |

### Alerts & Detections

| Table | Description | Key Fields |
|-------|-------------|------------|
| `notice` | Zeek notices/alerts | `uid`, `note`, `msg`, `severity_name` |
| `suricata` | Suricata IDS alerts | `uid`, `signature`, `signature_id`, `category`, `severity` |
| `alerts` | **Unified alerts** (notice + suricata) | `alert_type`, `alert_name`, `alert_detail`, `severity` |
| `weird` | Protocol anomalies | `uid`, `name`, `addl` |

### Certificates & Encryption

| Table | Description | Key Fields |
|-------|-------------|------------|
| `x509` | X.509 certificates | `fingerprint`, `subject`, `issuer`, `san_dns`, `not_valid_after` |

### Pre-Computed Lookup Tables (Fastest)

| Table | Purpose | Key Fields |
|-------|---------|------------|
| `uid_lookup` | Find all logs for a session UID | `uid`, `log_type`, `ts`, `orig_h`, `resp_h` |
| `fuid_lookup` | Find file details by FUID | `fuid`, `uid`, `mime_type`, `sha256` |

### Other Log Types

All 58 Corelight log types are available. Additional tables include:
- `http2`, `quic`, `websocket` - Modern protocols
- `tunnel`, `vpn`, `wireguard`, `ipsec` - VPN/tunneling
- `mysql`, `redis`, `ldap_search` - Database protocols
- `ntp`, `snmp`, `ssdp` - Network services
- `pe` - Portable executable analysis
- `software` - Detected software versions
- `known_hosts`, `known_services`, `known_devices`, `known_domains` - Asset inventory

---

## Common Field Mappings

### Connection Identifiers
- **`uid`** - Unique session identifier. Links logs across types (same uid = same network session)
- **`fuid`** - File unique identifier. Links file-related events
- **`community_id`** - Standardized flow hash (1:xxx format)

### IP/Port Fields
- **`orig_h`** - Source/originator IP address
- **`orig_p`** - Source port
- **`resp_h`** - Destination/responder IP address  
- **`resp_p`** - Destination port

### Network Context (Corelight-specific)
- **`orig_network_name`** - Network/VLAN name for source (e.g., "General WiFi", "Training Room 4412")
- **`orig_network_ssid`** - WiFi SSID if applicable
- **`orig_room_name`** - Physical location mapping

### Timestamps
- **`ts`** - Unix epoch timestamp (double)
- **`ts_datetime`** - Human-readable timestamp (string: `YYYY-MM-DD HH:MM:SS`)
- **`dt`** - Partition date (string: `YYYY-MM-DD`) - **ALWAYS filter on this**

---

## Query Patterns

### Basic Query Structure

```sql
SELECT columns
FROM blackhat_pope_logs.table_name
WHERE dt = 'YYYY-MM-DD'  -- REQUIRED for performance
  AND other_conditions
LIMIT n
```

### 1. Query by IP Address

```sql
-- Find all connections from an IP
SELECT ts_datetime, uid, orig_h, orig_p, resp_h, resp_p, proto, service, duration
FROM blackhat_pope_logs.conn
WHERE dt = '2026-04-22'
  AND orig_h = '10.220.38.21'
ORDER BY ts DESC
LIMIT 100

-- Find all connections to an IP
SELECT ts_datetime, uid, orig_h, orig_p, resp_h, resp_p, proto, service
FROM blackhat_pope_logs.conn
WHERE dt = '2026-04-22'
  AND resp_h = '8.8.8.8'
LIMIT 100
```

### 2. Query by UID (Session Pivot)

```sql
-- Find all logs related to a session UID (FASTEST - uses pre-computed index)
SELECT uid, log_type, ts, orig_h, resp_h, orig_network_name
FROM blackhat_pope_logs.uid_lookup
WHERE dt = '2026-04-22'
  AND uid = 'CzIENj4a7IGKR8UWed'
ORDER BY ts

-- Get full connection details for a UID
SELECT *
FROM blackhat_pope_logs.conn
WHERE dt = '2026-04-22'
  AND uid = 'CzIENj4a7IGKR8UWed'

-- Get DNS queries for a session
SELECT ts_datetime, query, qtype_name, answers
FROM blackhat_pope_logs.dns
WHERE dt = '2026-04-22'
  AND uid = 'CzIENj4a7IGKR8UWed'

-- Get HTTP requests for a session
SELECT ts_datetime, method, host, uri, status_code, user_agent
FROM blackhat_pope_logs.http
WHERE dt = '2026-04-22'
  AND uid = 'CzIENj4a7IGKR8UWed'
```

### 3. Query Alerts

```sql
-- Get all alerts (unified notice + suricata)
SELECT ts_datetime, alert_type, alert_name, alert_detail, severity, orig_h, resp_h
FROM blackhat_pope_logs.alerts
WHERE dt = '2026-04-22'
ORDER BY ts DESC
LIMIT 100

-- Get alerts by severity
SELECT ts_datetime, alert_type, alert_name, orig_h, resp_h, uid
FROM blackhat_pope_logs.alerts
WHERE dt = '2026-04-22'
  AND severity IN ('1', '2', 'critical', 'error')
LIMIT 100

-- Top alerts by count
SELECT alert_name, alert_type, COUNT(*) as count
FROM blackhat_pope_logs.alerts
WHERE dt = '2026-04-22'
GROUP BY alert_name, alert_type
ORDER BY count DESC
LIMIT 20

-- Alerts for a specific IP
SELECT ts_datetime, alert_type, alert_name, alert_detail, uid
FROM blackhat_pope_logs.alerts
WHERE dt = '2026-04-22'
  AND (orig_h = '10.220.38.21' OR resp_h = '10.220.38.21')
ORDER BY ts DESC
```

### 4. DNS Queries

```sql
-- Search for domain queries
SELECT ts_datetime, orig_h, query, qtype_name, answers, orig_network_name
FROM blackhat_pope_logs.dns
WHERE dt = '2026-04-22'
  AND query LIKE '%microsoft.com%'
LIMIT 100

-- Find queries to suspicious TLDs
SELECT ts_datetime, orig_h, query, answers, orig_network_name
FROM blackhat_pope_logs.dns
WHERE dt = '2026-04-22'
  AND (icann_tld = 'ru' OR icann_tld = 'cn' OR icann_tld = 'xyz')
LIMIT 100

-- DNS query statistics by domain
SELECT icann_domain, COUNT(*) as query_count
FROM blackhat_pope_logs.dns
WHERE dt = '2026-04-22'
GROUP BY icann_domain
ORDER BY query_count DESC
LIMIT 50
```

### 5. File Analysis

```sql
-- Find files by hash
SELECT ts_datetime, fuid, uid, orig_h, resp_h, mime_type, filename, seen_bytes
FROM blackhat_pope_logs.files
WHERE dt = '2026-04-22'
  AND sha256 = '5281ebc6a6cfeb71f183036e1d1fcb228bfed1a54898323fbbd19732cdb7be40'

-- Find files by FUID (uses pre-computed index)
SELECT *
FROM blackhat_pope_logs.fuid_lookup
WHERE dt = '2026-04-22'
  AND fuid = 'FsNiuH2kQN4C4YZoHj'

-- Find executable files
SELECT ts_datetime, fuid, uid, orig_h, resp_h, filename, mime_type, sha256, seen_bytes
FROM blackhat_pope_logs.files
WHERE dt = '2026-04-22'
  AND (mime_type LIKE '%executable%' OR mime_type LIKE '%x-dosexec%' OR filename LIKE '%.exe')
LIMIT 100

-- Large file transfers
SELECT ts_datetime, fuid, orig_h, resp_h, mime_type, filename, seen_bytes
FROM blackhat_pope_logs.files
WHERE dt = '2026-04-22'
  AND seen_bytes > 10000000  -- > 10MB
ORDER BY seen_bytes DESC
LIMIT 50
```

### 6. SSL/TLS Analysis

```sql
-- Find connections by server name (SNI)
SELECT ts_datetime, uid, orig_h, resp_h, server_name, version, cipher, ja3
FROM blackhat_pope_logs.ssl
WHERE dt = '2026-04-22'
  AND server_name LIKE '%discord%'
LIMIT 100

-- Find by JA3 fingerprint
SELECT ts_datetime, orig_h, resp_h, server_name, ja3, ja3s
FROM blackhat_pope_logs.ssl
WHERE dt = '2026-04-22'
  AND ja3 = 'e7d705a3286e19ea42f587b344ee6865'
LIMIT 100

-- Self-signed or expired certificate alerts
SELECT ts_datetime, uid, orig_h, resp_h, note, msg
FROM blackhat_pope_logs.notice
WHERE dt = '2026-04-22'
  AND note LIKE 'SSL::%'
LIMIT 100
```

### 7. Network Statistics

```sql
-- Top talkers by bytes
SELECT orig_h, 
       SUM(CAST(orig_bytes AS bigint)) as bytes_sent,
       SUM(CAST(resp_bytes AS bigint)) as bytes_received,
       COUNT(*) as connection_count
FROM blackhat_pope_logs.conn
WHERE dt = '2026-04-22'
GROUP BY orig_h
ORDER BY bytes_sent DESC
LIMIT 20

-- Connections by network/room
SELECT orig_network_name, COUNT(*) as conn_count
FROM blackhat_pope_logs.conn
WHERE dt = '2026-04-22'
GROUP BY orig_network_name
ORDER BY conn_count DESC
LIMIT 20

-- Protocol distribution
SELECT proto, service, COUNT(*) as count
FROM blackhat_pope_logs.conn
WHERE dt = '2026-04-22'
GROUP BY proto, service
ORDER BY count DESC
LIMIT 30
```

### 8. Time-Based Queries

```sql
-- Activity in a time window (using epoch timestamp)
SELECT ts_datetime, uid, orig_h, resp_h, proto, service
FROM blackhat_pope_logs.conn
WHERE dt = '2026-04-22'
  AND ts BETWEEN 1776752400 AND 1776756000  -- 1 hour window
ORDER BY ts
LIMIT 1000

-- Activity for last N hours (relative)
SELECT ts_datetime, uid, orig_h, resp_h, proto, service
FROM blackhat_pope_logs.conn
WHERE dt = '2026-04-22'
  AND ts > (to_unixtime(now()) - 3600)  -- last hour
ORDER BY ts DESC
LIMIT 100
```


---

## API Integration

### Python (boto3)

```python
import boto3
import time

class AthenaQueryClient:
    def __init__(self, region='us-west-2'):
        self.athena = boto3.client('athena', region_name=region)
        self.database = 'blackhat_pope_logs'
        self.workgroup = 'blackhat-pope-dev'
    
    def execute_query(self, query, wait=True, timeout=300):
        """Execute Athena query and optionally wait for results."""
        response = self.athena.start_query_execution(
            QueryString=query,
            QueryExecutionContext={'Database': self.database},
            WorkGroup=self.workgroup
        )
        query_id = response['QueryExecutionId']
        
        if not wait:
            return query_id, None
        
        # Wait for completion
        start_time = time.time()
        while time.time() - start_time < timeout:
            result = self.athena.get_query_execution(QueryExecutionId=query_id)
            state = result['QueryExecution']['Status']['State']
            
            if state == 'SUCCEEDED':
                return query_id, self._get_results(query_id)
            elif state in ['FAILED', 'CANCELLED']:
                error = result['QueryExecution']['Status'].get('StateChangeReason', 'Unknown error')
                raise Exception(f"Query failed: {error}")
            
            time.sleep(1)
        
        raise TimeoutError(f"Query timed out after {timeout}s")
    
    def _get_results(self, query_id):
        """Fetch query results as list of dicts."""
        results = []
        paginator = self.athena.get_paginator('get_query_results')
        
        for page in paginator.paginate(QueryExecutionId=query_id):
            rows = page['ResultSet']['Rows']
            if not results:  # First page includes header
                headers = [col['VarCharValue'] for col in rows[0]['Data']]
                rows = rows[1:]
            
            for row in rows:
                values = [col.get('VarCharValue', '') for col in row['Data']]
                results.append(dict(zip(headers, values)))
        
        return results
    
    # Convenience methods
    def query_by_uid(self, uid, date):
        """Get all logs for a session UID."""
        query = f"""
        SELECT uid, log_type, ts, orig_h, resp_h, orig_network_name
        FROM uid_lookup
        WHERE dt = '{date}' AND uid = '{uid}'
        ORDER BY ts
        """
        return self.execute_query(query)[1]
    
    def query_by_ip(self, ip, date, limit=100):
        """Get connections for an IP address."""
        query = f"""
        SELECT ts_datetime, uid, orig_h, orig_p, resp_h, resp_p, proto, service
        FROM conn
        WHERE dt = '{date}' AND (orig_h = '{ip}' OR resp_h = '{ip}')
        ORDER BY ts DESC LIMIT {limit}
        """
        return self.execute_query(query)[1]
    
    def get_alerts(self, date, severity=None, limit=100):
        """Get alerts, optionally filtered by severity."""
        severity_filter = f"AND severity IN ({severity})" if severity else ""
        query = f"""
        SELECT ts_datetime, alert_type, alert_name, alert_detail, severity, orig_h, resp_h, uid
        FROM alerts
        WHERE dt = '{date}' {severity_filter}
        ORDER BY ts DESC LIMIT {limit}
        """
        return self.execute_query(query)[1]
    
    def search_dns(self, pattern, date, limit=100):
        """Search DNS queries by domain pattern."""
        query = f"""
        SELECT ts_datetime, orig_h, query, qtype_name, answers, orig_network_name
        FROM dns
        WHERE dt = '{date}' AND query LIKE '%{pattern}%'
        LIMIT {limit}
        """
        return self.execute_query(query)[1]
    
    def get_file_by_hash(self, hash_value, date):
        """Find file by MD5, SHA1, or SHA256."""
        query = f"""
        SELECT ts_datetime, fuid, uid, orig_h, resp_h, mime_type, filename, seen_bytes, md5, sha1, sha256
        FROM files
        WHERE dt = '{date}'
          AND (md5 = '{hash_value}' OR sha1 = '{hash_value}' OR sha256 = '{hash_value}')
        """
        return self.execute_query(query)[1]


# Usage example
if __name__ == '__main__':
    client = AthenaQueryClient()
    
    # Query by UID
    results = client.query_by_uid('CzIENj4a7IGKR8UWed', '2026-04-22')
    print(f"Found {len(results)} log entries for UID")
    
    # Get alerts
    alerts = client.get_alerts('2026-04-22', limit=10)
    for alert in alerts:
        print(f"{alert['ts_datetime']} - {alert['alert_name']}")
```

### AWS CLI

```bash
# Set defaults
export AWS_REGION=us-west-2
export AWS_PROFILE=VirtualPOC-admins  # Or use instance role on EC2

# Execute query
QUERY_ID=$(aws athena start-query-execution \
  --work-group blackhat-pope-dev \
  --query-execution-context Database=blackhat_pope_logs \
  --query-string "SELECT * FROM conn WHERE dt='2026-04-22' LIMIT 10" \
  --query 'QueryExecutionId' --output text)

# Wait and get results
aws athena get-query-execution --query-execution-id $QUERY_ID
aws athena get-query-results --query-execution-id $QUERY_ID --output json
```

### Using athenacli (Interactive SQL)

```bash
# Install
pip install athenacli

# Connect with default database
athenacli --region us-west-2 --work-group blackhat-pope-dev --database blackhat_pope_logs

# Then run queries directly:
# > SELECT * FROM conn WHERE dt='2026-04-22' LIMIT 10;
# > SELECT * FROM alerts WHERE dt='2026-04-22' LIMIT 10;
```

---

## Performance Tips

### 1. ALWAYS Filter by Date Partition
```sql
-- GOOD: Uses partition pruning, scans only one day
SELECT * FROM conn WHERE dt = '2026-04-22' AND orig_h = '10.0.0.1'

-- BAD: Scans ALL data, slow and expensive
SELECT * FROM conn WHERE orig_h = '10.0.0.1'
```

### 2. Use Pre-Computed Lookup Tables
```sql
-- FAST: Pre-computed UID index (~1 second)
SELECT * FROM uid_lookup WHERE uid = 'CzIENj4a7IGKR8UWed' AND dt = '2026-04-22'

-- SLOWER: Scans full conn table
SELECT * FROM conn WHERE uid = 'CzIENj4a7IGKR8UWed' AND dt = '2026-04-22'
```

### 3. Select Only Needed Columns
```sql
-- GOOD: Only fetches required columns
SELECT ts_datetime, orig_h, resp_h, proto FROM conn WHERE dt = '2026-04-22' LIMIT 100

-- LESS EFFICIENT: Fetches all columns
SELECT * FROM conn WHERE dt = '2026-04-22' LIMIT 100
```

### 4. Use LIMIT for Exploration
```sql
-- Always use LIMIT when exploring
SELECT * FROM conn WHERE dt = '2026-04-22' LIMIT 100
```

### 5. Expected Query Performance
| Query Type | Typical Time | Data Scanned |
|------------|--------------|--------------|
| UID lookup (index) | < 2 sec | ~300 MB |
| Single table filter | 1-3 sec | ~10-50 MB |
| Aggregation (GROUP BY) | 2-5 sec | ~10-100 MB |
| Full day scan | 5-15 sec | ~500 MB - 2 GB |

---

## EC2 Instance Details (AING)

The AING EC2 instance is pre-configured with Athena access.

| Property | Value |
|----------|-------|
| **Instance ID** | `<INSTANCE-ID>` |
| **Type** | g6e.4xlarge |
| **Public IP** | `<EC2-PUBLIC-IP>` |
| **DNS** | `aing.bhnoc.com` |
| **IAM Role** | `blackhat-pope-dev-ec2-role` |
| **SSH** | `ssh ubuntu@aing.bhnoc.com` |

The instance role already has all required Athena, Glue, and S3 permissions.

---

## Data Refresh Schedule

### During Conference (Apr 22-25, 2026)
- **Hourly refresh** enabled via Lambda `blackhat-pope-athena-refresh`
- New log types automatically detected and converted to Parquet
- UID/FUID/alerts indexes rebuilt with new data

### After Conference (Apr 26+)
- Auto-disabled Saturday Apr 26 01:00 SGT
- No cost when idle
- Re-enable with: `aws events enable-rule --name blackhat-pope-athena-hourly`

### Manual Refresh
```bash
aws lambda invoke --function-name blackhat-pope-athena-refresh \
  --invocation-type Event \
  --payload '{"date": "2026-04-22"}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/out.json --region us-west-2
```

---

## Corelight Log Concepts

### Session Correlation via UID
Every network session gets a unique `uid`. This ID appears across multiple log types:

```
conn log:     uid=CzIENj4a7IGKR8UWed  (TCP connection established)
    │
    ├── dns log:   uid=CzIENj4a7IGKR8UWed  (DNS query over this connection)
    ├── http log:  uid=CzIENj4a7IGKR8UWed  (HTTP request)
    ├── ssl log:   uid=CzIENj4a7IGKR8UWed  (TLS handshake)
    ├── files log: uid=CzIENj4a7IGKR8UWed  (File transfer)
    └── notice:    uid=CzIENj4a7IGKR8UWed  (Alert triggered)
```

Use `uid_lookup` to quickly find all log types for a session.

### File Correlation via FUID
Files get a unique `fuid` that links across file-related logs:

```
files log:    fuid=FsNiuH2kQN4C4YZoHj  (File metadata, hashes)
    │
    └── pe log:   fuid=FsNiuH2kQN4C4YZoHj  (PE executable analysis)
```

Use `fuid_lookup` to quickly find file details.

### Network Context Fields
Corelight adds rich context to every log:
- `orig_network_name` - Network/VLAN name (e.g., "Training Room 4412")
- `orig_network_ssid` - WiFi SSID
- `remote_organization` - GeoIP organization (e.g., "Amazon.com, Inc.")
- `remote_country` - GeoIP country code

---

## Troubleshooting

### Query Times Out
- Add `LIMIT` clause
- Ensure `dt = 'YYYY-MM-DD'` filter is present
- Check if workgroup has query timeout configured

### No Results Returned
- Verify date partition exists: Check S3 bucket for that date
- Check column names match (case-sensitive)
- Verify filter values (IPs, UIDs are exact match)

### Permission Denied
- Verify IAM role has all permissions from the IAM section above
- Check workgroup access
- Ensure S3 bucket policies allow access

### Data Not Updated
- Manual refresh: Invoke `blackhat-pope-athena-refresh` Lambda
- Check Lambda logs: `/aws/lambda/blackhat-pope-athena-refresh`
- Verify new data exists in source bucket

---

## Contact & Resources

- **AWS Account:** <ACCOUNT-ID> (Virtual POC)
- **Region:** us-west-2
- **Owner:** <OWNER-EMAIL>
- **Project:** BlackHat-Pope
