# PB-01: C2 Beaconing Detection

**ATT&CK**: T1071 (Application Layer Protocol), T1095 (Non-Application Layer Protocol), T1102 (Web Service)
**Data Sources**: Zeek conn.log, NetFlow, Suricata flow events
**Tools**: RITA, Python/pandas, tshark, Brim/ZQL

## Hypothesis

An implanted host is maintaining persistence by sending periodic small connections to a C2 server on a regular schedule. This "beaconing" behavior is statistically distinctive even when the traffic blends into normal HTTPS or HTTP traffic.

## Detection Logic

### Method 1: RITA (Automated)

```bash
# Install RITA (from GitHub)
# Feed Zeek logs from target time range
rita import /path/to/zeek/logs/ my-dataset

# View beaconing results
rita show-beacons my-dataset | head -50

# View DNS tunneling
rita show-dns-fqdns my-dataset | head -30

# View blacklisted connections
rita show-bl-hostnames my-dataset | head -20
```

RITA scores: **0.0 = no beacon, 1.0 = perfect beacon**. Focus on scores > 0.7.

### Method 2: Manual Statistical Analysis (Python)

```python
import pandas as pd
import numpy as np

# Load Zeek conn.log (TSV)
df = pd.read_csv('conn.log', sep='\t', comment='#',
                 names=['ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p',
                        'proto','service','duration','orig_bytes','resp_bytes',
                        'conn_state','local_orig','local_resp','missed_bytes',
                        'history','orig_pkts','orig_ip_bytes','resp_pkts','resp_ip_bytes','tunnel_parents'])

df['ts'] = pd.to_numeric(df['ts'], errors='coerce')

# Group by src-dst pair, calculate interval statistics
def analyze_pair(group):
    if len(group) < 10:  # Need enough samples
        return None
    group = group.sort_values('ts')
    intervals = group['ts'].diff().dropna()
    return pd.Series({
        'count': len(group),
        'interval_mean': intervals.mean(),
        'interval_std': intervals.std(),
        'interval_cv': intervals.std() / intervals.mean() if intervals.mean() > 0 else 999,
        'bytes_mean': group['orig_bytes'].mean(),
        'bytes_std': group['orig_bytes'].std(),
    })

pairs = df.groupby(['id.orig_h', 'id.resp_h']).apply(analyze_pair).dropna()

# Low coefficient of variation = regular interval = beacon
beacons = pairs[pairs['interval_cv'] < 0.2].sort_values('interval_cv')
print(beacons.head(20))
```

### Method 3: tshark Beacon Extraction

```bash
# Extract all connection timings for a specific dst IP
tshark -r cap.pcap -T fields -e frame.time_epoch -e ip.src -e ip.dst \
  -Y "ip.dst == 1.2.3.4" | awk '{print $1}' | sort -n > /tmp/times.txt

# Calculate intervals with awk
awk 'NR>1{printf "%.3f\n", $1-prev} {prev=$1}' /tmp/times.txt | sort -n
```

### Method 4: Zeek Scripting (Inline Detection)

```zeek
# Simplified beaconing detector in Zeek
global conn_tracker: table[addr, addr] of vector of time;

event connection_established(c: connection) {
    local key = [c$id$orig_h, c$id$resp_h];
    if (key !in conn_tracker)
        conn_tracker[key] = vector();
    conn_tracker[key] += network_time();
}
```

### Method 5: Brim/ZQL Query

```
# In Brim, find high-frequency connections with consistent small byte sizes
from conn.log
| where _path == "conn"
| summarize count := count(), bytes_mean := mean(orig_bytes),
            bytes_std := stddev(orig_bytes)
  by id.orig_h, id.resp_h, id.resp_p
| where count > 50 and bytes_std < 100
| sort -count
```

## Behavioral Indicators

| Indicator | Threshold | Notes |
|-----------|-----------|-------|
| Connection interval CoV < 0.2 | High confidence | Very regular intervals |
| Connection count to same dst > 50/hour | Medium | High frequency |
| Consistent small byte sizes (50–500 bytes) | Medium | Heartbeat traffic |
| Connections at odd hours (0200–0500) | Low-medium | Attacker may be in different timezone |
| Single dst port (usually 80, 443, or 53) | Context-dependent | Blending into normal traffic |

## Tuning / False Positive Reduction

- Whitelist known NTP servers (port 123, very regular)
- Whitelist known monitoring agents (SNMP, Nagios, etc.)
- Whitelist backup/sync software with regular schedules
- Focus on non-CDN external IPs (use ASN lookups to exclude Cloudflare, Akamai, etc.)
- Require minimum connection count of 10+ before scoring

## Response

1. Enrich dst IP/domain via VirusTotal, Shodan, AbuseIPDB
2. Review full PCAP for the beaconing session — look for config/command patterns
3. Extract any downloaded files (files.log → hash → VT)
4. Isolate affected host from network
5. Preserve memory dump for C2 artifact extraction
6. Check for lateral movement from the affected host during beaconing period

## Sources

- [RITA (activecm)](https://github.com/activecm/rita)
- [Active Countermeasures — Threat Hunting with Zeek and RITA](https://www.activecountermeasures.com/threat-hunting-over-the-network-with-zeek-and-rita/)
- [CISA — RITA](https://www.cisa.gov/resources-tools/services/rita)
