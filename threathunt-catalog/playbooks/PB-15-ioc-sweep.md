# PB-15: Retrospective IOC Sweep

**ATT&CK**: Supporting all tactics — retrohunt finds past compromise based on new intel
**Data Sources**: All historical Zeek logs, Suricata eve.json, PCAP archive
**Tools**: Zeek, grep, Python, Arkime, MISP, tshark

## Overview

When new threat intelligence is published (IOCs from an incident, vendor advisory, ISAC feed), retroactively sweep all historical network logs for any match. This identifies dwell-time breaches — compromises that happened before the IOC was known.

---

## Step 1: Gather IOCs

```bash
# From MISP — export IOC list
curl -s "https://misp.your-org.com/attributes/restSearch" \
  -H "Authorization: $MISP_KEY" \
  -H "Accept: application/json" \
  -d '{"returnFormat": "json", "type": ["ip-dst", "domain", "md5", "sha256"],
       "tags": ["tlp:white"], "to_ids": true}' | \
  jq -r '.response.Attribute[] | [.type, .value] | @tsv' > /tmp/iocs.tsv

# Split by type
awk -F'\t' '$1 ~ /^ip/' /tmp/iocs.tsv | cut -f2 > /tmp/bad_ips.txt
awk -F'\t' '$1 == "domain"' /tmp/iocs.tsv | cut -f2 > /tmp/bad_domains.txt
awk -F'\t' '$1 ~ /md5|sha256/' /tmp/iocs.tsv | cut -f2 > /tmp/bad_hashes.txt

echo "IOCs loaded: $(wc -l /tmp/bad_ips.txt) IPs, $(wc -l /tmp/bad_domains.txt) domains, $(wc -l /tmp/bad_hashes.txt) hashes"
```

---

## Step 2: Sweep Zeek Logs (Local or Archived)

### IP IOC Sweep

```bash
#!/bin/bash
# sweep_ips.sh — Sweep all Zeek conn.log files for bad IPs

LOG_DIR="/var/log/zeek"
BAD_IPS="/tmp/bad_ips.txt"
RESULTS="/tmp/ip_sweep_results.txt"

> "$RESULTS"

find "$LOG_DIR" -name "conn*.log*" | while read logfile; do
  # Handle both plain and gzipped logs
  if [[ "$logfile" == *.gz ]]; then
    reader="zcat"
  else
    reader="cat"
  fi
  
  $reader "$logfile" | zeek-cut ts id.orig_h id.resp_h id.resp_p proto orig_bytes resp_bytes | \
    grep -Ff "$BAD_IPS" | \
    sed "s/^/$(basename $logfile)\t/" >> "$RESULTS"
done

echo "=== Results ==="
sort "$RESULTS" | uniq -c | sort -rn | head -50
```

### Domain IOC Sweep

```bash
#!/bin/bash
# sweep_domains.sh — Sweep dns.log and http.log for bad domains

LOG_DIR="/var/log/zeek"
BAD_DOMAINS="/tmp/bad_domains.txt"

echo "=== DNS log hits ==="
find "$LOG_DIR" -name "dns*.log*" | while read logfile; do
  cmd="cat"; [[ "$logfile" == *.gz ]] && cmd="zcat"
  $cmd "$logfile" | zeek-cut ts id.orig_h query rcode_name | \
    grep -Ff "$BAD_DOMAINS" | head -10
done

echo ""
echo "=== HTTP log hits ==="
find "$LOG_DIR" -name "http*.log*" | while read logfile; do
  cmd="cat"; [[ "$logfile" == *.gz ]] && cmd="zcat"
  $cmd "$logfile" | zeek-cut ts id.orig_h host uri | \
    grep -Ff "$BAD_DOMAINS" | head -10
done

echo ""
echo "=== SSL/TLS log hits (SNI) ==="
find "$LOG_DIR" -name "ssl*.log*" | while read logfile; do
  cmd="cat"; [[ "$logfile" == *.gz ]] && cmd="zcat"
  $cmd "$logfile" | zeek-cut ts id.orig_h id.resp_h server_name | \
    grep -Ff "$BAD_DOMAINS" | head -10
done
```

### Hash IOC Sweep

```bash
#!/bin/bash
# sweep_hashes.sh — Sweep files.log for bad file hashes

LOG_DIR="/var/log/zeek"
BAD_HASHES="/tmp/bad_hashes.txt"

echo "=== File hash hits ==="
find "$LOG_DIR" -name "files*.log*" | while read logfile; do
  cmd="cat"; [[ "$logfile" == *.gz ]] && cmd="zcat"
  $cmd "$logfile" | zeek-cut ts tx_hosts rx_hosts filename mime_type md5 sha256 | \
    grep -Ff "$BAD_HASHES" | head -10
done
```

---

## Step 3: Arkime Search (If Available)

```bash
# Arkime REST API search for bad IPs
# Set ARKIME_USER and ARKIME_PASS to your Arkime credentials before running
curl -s "http://arkime:8005/api/sessions" \
  -u "${ARKIME_USER:-admin}:${ARKIME_PASS}" \
  -d "expression=ip.dst%20%3D%3D%201.2.3.4&startTime=1704067200&stopTime=$(date +%s)" | \
  jq '.data[] | {start: .startTime, src: .srcIp, dst: .dstIp, bytes: .totDataBytes}'

# Arkime UI search (browser)
# Expression: ip.dst == 1.2.3.4
# Expression: host == evil.domain.com
# Expression: dns.host == suspicious.domain.com
```

---

## Step 4: PCAP-Level Sweep (For Confirmed IOC Hits)

```bash
# Once a hit is found in Zeek logs, retrieve corresponding PCAP from Arkime/Stenographer
# and do a deep dive

# Stenographer retrieval by IP and time range
stenoread "host 1.2.3.4 and after 2024-01-01T00:00:00Z and before 2024-01-02T00:00:00Z" \
  > /tmp/suspect_session.pcap

# Analyze retrieved PCAP
zeek -r /tmp/suspect_session.pcap
wireshark /tmp/suspect_session.pcap &

# tshark quick summary
tshark -r /tmp/suspect_session.pcap -z conv,tcp -q | head -20
```

---

## Step 5: Timeline Reconstruction

```bash
# For each confirmed IOC hit, reconstruct the full timeline

SUSPECT_IP="10.0.0.50"  # Internal host that hit a bad IOC

# All connections from suspect host around the hit time
zeek-cut ts id.orig_h id.resp_h id.resp_p service orig_bytes resp_bytes < conn.log | \
  awk -F'\t' '$2 == "'$SUSPECT_IP'"' | sort -k1 | head -50

# DNS queries from suspect host
zeek-cut ts id.orig_h query rcode_name < dns.log | \
  awk -F'\t' '$2 == "'$SUSPECT_IP'"' | sort -k1 | head -30

# Files transferred by suspect host
zeek-cut ts id.orig_h id.resp_h filename mime_type md5 < files.log | \
  awk -F'\t' '$2 == "'$SUSPECT_IP'" || $3 == "'$SUSPECT_IP'"' | sort -k1 | head -20

# HTTP activity from suspect host
zeek-cut ts id.orig_h host uri user_agent < http.log | \
  awk -F'\t' '$2 == "'$SUSPECT_IP'"' | sort -k1 | head -30
```

---

## Step 6: Scope — All Affected Hosts

```bash
# Find ALL internal hosts that communicated with bad IPs
echo "=== All hosts touching bad IPs ==="
zeek-cut id.orig_h id.resp_h < conn.log | \
  awk -F'\t' 'NR==FNR{bad[$0]=1;next} $2 in bad {print $1}' \
  /tmp/bad_ips.txt - | sort -u

# Find ALL hosts that queried bad domains
echo "=== All hosts querying bad domains ==="
zeek-cut id.orig_h query < dns.log | \
  awk -F'\t' 'NR==FNR{bad[$0]=1;next} $2 in bad {print $1}' \
  /tmp/bad_domains.txt - | sort -u
```

---

## Automation: Scheduled IOC Sweep

```python
#!/usr/bin/env python3
"""Automated IOC sweep — runs against latest 24h of Zeek logs."""

import subprocess, json, requests
from datetime import datetime, timedelta

MISP_URL = "https://misp.your-org.com"
MISP_KEY = "your_key"
ZEEK_LOG_DIR = "/var/log/zeek/current"

def fetch_misp_iocs():
    """Fetch fresh IOCs from MISP."""
    r = requests.post(f"{MISP_URL}/attributes/restSearch",
                      headers={"Authorization": MISP_KEY, "Accept": "application/json"},
                      json={"returnFormat": "json", "type": ["ip-dst", "domain"],
                            "to_ids": True, "last": "1d"})  # Last 24 hours
    iocs = {"ips": [], "domains": []}
    for attr in r.json().get("response", {}).get("Attribute", []):
        if "ip" in attr["type"]:
            iocs["ips"].append(attr["value"])
        elif attr["type"] == "domain":
            iocs["domains"].append(attr["value"])
    return iocs

def sweep_conn_log(bad_ips):
    """Sweep conn.log for bad IPs."""
    hits = []
    result = subprocess.run(
        ["zeek-cut", "ts", "id.orig_h", "id.resp_h", "id.resp_p"],
        stdin=open(f"{ZEEK_LOG_DIR}/conn.log"),
        capture_output=True, text=True
    )
    for line in result.stdout.splitlines():
        parts = line.split('\t')
        if len(parts) >= 4 and parts[2] in bad_ips:
            hits.append({"ts": parts[0], "src": parts[1], "dst": parts[2], "port": parts[3]})
    return hits

if __name__ == "__main__":
    iocs = fetch_misp_iocs()
    print(f"Fetched {len(iocs['ips'])} IPs, {len(iocs['domains'])} domains")
    
    ip_hits = sweep_conn_log(set(iocs['ips']))
    if ip_hits:
        print(f"ALERT: {len(ip_hits)} hits in conn.log!")
        for hit in ip_hits[:10]:
            print(f"  {hit}")
    else:
        print("No IOC hits found.")
```

---

## Prioritization Guide

| Hit Type | Priority | Why |
|----------|----------|-----|
| IOC in conn.log AND files.log (file downloaded) | CRITICAL | Payload delivered |
| IOC in dns.log (multiple lookups) | HIGH | Active C2 communication likely |
| IOC in ssl.log (connection established) | HIGH | Encrypted channel to known-bad |
| IOC in conn.log (connection state SF = successful) | MEDIUM | Confirmed communication |
| IOC in conn.log (state S0 = SYN only) | LOW | May be scanner; dest didn't respond |
| IOC only in dns.log (NXDOMAIN) | LOW | DNS query but no connection established |

## Sources

- [MISP Project](https://www.misp-project.org/)
- [AlienVault OTX](https://otx.alienvault.com/)
- [Arkime (formerly Moloch)](https://arkime.com/)
- [RITA GitHub](https://github.com/activecm/rita)
- [Threat Hunting Playbooks — SOC Edition (cyberopshub.io)](https://cyberopshub.io/resource.php?slug=soc-threat-hunting-playbook)
