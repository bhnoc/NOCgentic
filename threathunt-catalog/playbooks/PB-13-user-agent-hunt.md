# PB-13: Anomalous User-Agent & HTTP Pattern Hunting

**ATT&CK**: T1071.001 (Web Protocols), T1132 (Data Encoding)
**Data Sources**: Zeek http.log; Suricata http events; PCAP
**Tools**: Zeek, tshark, Brim, Python

## Hypothesis

Malware and C2 implants often use non-browser HTTP user-agents, either default library strings (Python urllib, Go net/http, curl) or hardcoded strings. These stand out against the browser-dominated normal traffic.

---

## Detection: Rare / Anomalous User-Agents

```bash
# Zeek: frequency count all user-agents
zeek-cut user_agent < http.log | sort | uniq -c | sort -rn > /tmp/ua_freq.txt
cat /tmp/ua_freq.txt | head -30

# Flag non-browser user-agents (absent of common browser strings)
zeek-cut ts id.orig_h host user_agent < http.log | \
  awk -F'\t' '$4 != "" && $4 !~ /Mozilla|Chrome|Safari|Firefox|Edge|Opera|Googlebot|Bingbot/' | \
  sort | uniq -c | sort -rn | head -30

# Known suspicious UA patterns
SUSPICIOUS_UA="python-requests|python-urllib|Go-http-client|curl/|wget/|PowerShell|libwww-perl|masscan|nmap|zgrab|sqlmap|nikto|dirbuster"
zeek-cut ts id.orig_h host uri user_agent < http.log | \
  awk -F'\t' -v pattern="$SUSPICIOUS_UA" '$5 ~ pattern' | sort | uniq -c | sort -rn

# tshark equivalent
tshark -r cap.pcap -Y 'http.request' -T fields -e ip.src -e http.host \
  -e http.request.uri -e http.user_agent | \
  grep -Ev 'Mozilla|Chrome|Safari|Firefox|Edge' | head -30
```

---

## Detection: Empty or Missing User-Agent

```bash
# Malware often sends HTTP requests with no User-Agent header
zeek-cut ts id.orig_h host uri user_agent < http.log | \
  awk -F'\t' '$5 == "" || $5 == "-"' | \
  awk -F'\t' '$2 !~ /^10\.|^172\.|^192\.168\./' | sort | uniq -c | sort -rn
```

---

## Detection: Same Host, Mixed User-Agents (Implant Masquerading)

```bash
# A host that alternates between a browser UA and a malware UA
# (implant may be spoofing browser UA but making structural mistakes)

zeek-cut id.orig_h user_agent < http.log | sort | uniq | \
  awk -F'\t' '{uas[$1][$2]=1} END {
    for (h in uas) {
      n=0; for (ua in uas[h]) n++
      if (n > 3) {
        printf "%s:\n", h
        for (ua in uas[h]) printf "  %s\n", ua
      }
    }
  }'
```

---

## Detection: HTTP Methods Anomalies

```bash
# Unusual HTTP methods (PUT, DELETE, PATCH, OPTIONS from non-API hosts)
zeek-cut id.orig_h host method uri < http.log | \
  awk -F'\t' '$3 ~ /^(PUT|DELETE|PATCH|CONNECT|OPTIONS)$/' | \
  sort | uniq -c | sort -rn | head -20

# HTTP CONNECT tunnel (proxy abuse or C2)
zeek-cut ts id.orig_h id.resp_h method host < http.log | \
  awk -F'\t' '$4 == "CONNECT"' | sort | uniq -c | sort -rn | head -10
```

---

## Detection: URI Pattern Anomalies

```bash
# URIs with high entropy (encoded C2 commands or data)
zeek-cut id.orig_h host uri < http.log | \
  python3 -c "
import sys, math
from collections import Counter

def entropy(s):
    freq = Counter(s)
    total = len(s)
    return -sum((c/total) * math.log2(c/total) for c in freq.values())

for line in sys.stdin:
    parts = line.strip().split('\t')
    if len(parts) < 3: continue
    uri = parts[2]
    if len(uri) > 20 and entropy(uri) > 4.5:
        print(f'{entropy(uri):.2f}\t{line.strip()}')
" | sort -rn | head -20

# Very long URIs (possible data encoding in GET params)
zeek-cut id.orig_h host uri < http.log | \
  awk -F'\t' 'length($3) > 500 {print length($3), $0}' | sort -rn | head -10
```

---

## Detection: Checksum8 URI Pattern (Cobalt Strike Default)

```bash
# Cobalt Strike's default HTTP profile uses 4-character URIs with specific patterns
zeek-cut ts id.orig_h host uri method < http.log | \
  awk -F'\t' '$3 ~ /^\/[a-zA-Z]{4,6}$/ && ($4 == "GET" || $4 == "POST")' | \
  sort | uniq -c | sort -rn | head -20
```

---

## Detection: HTTP Response Code Anomalies

```bash
# C2 servers often return non-standard response codes
zeek-cut ts id.orig_h host status_code < http.log | \
  awk -F'\t' '$4 ~ /^[0-9]+$/' | sort -k4 | uniq -c | sort -rn | head -30

# 404 responses to POST requests (unusual - legitimate 404s are usually GET)
zeek-cut id.orig_h host method status_code < http.log | \
  awk -F'\t' '$3=="POST" && $4=="404"' | sort | uniq -c | sort -rn
```

---

## JA4H HTTP Fingerprinting

```bash
# JA4H fingerprints HTTP based on: method, HTTP version, headers present/absent
# Available after installing JA4+ Zeek package

# Extract rare JA4H fingerprints (non-browser patterns)
zeek-cut ts id.orig_h host ja4h < http.log | sort | uniq -c | sort -n | head -30

# Typical browser JA4H: ge11cr10_XXXX_YYYY (GET, HTTP/1.1, 10 headers, cookies)
# Malware/C2: different header count, different order, no cookies
```

---

## Suricata HTTP Detection Rules

```bash
# Flag suspicious user agents
alert http any any -> any any (
  msg:"Suspicious UA — Python Requests";
  http.user_agent; content:"python-requests";
  sid:9004001; rev:1;)

alert http any any -> any any (
  msg:"Suspicious UA — Go HTTP Client";
  http.user_agent; content:"Go-http-client";
  sid:9004002; rev:1;)

alert http any any -> any any (
  msg:"Missing User-Agent on POST";
  http.method; content:"POST";
  http.header; content:!"User-Agent";
  sid:9004003; rev:1;)

alert http any any -> any any (
  msg:"PowerShell Download Cradle";
  http.user_agent; content:"PowerShell";
  sid:9004004; rev:1;)
```

## Sources

- [Threat Hunting with Tshark (hackforlab.com)](https://hackforlab.com/threat-hunting-with-tshark/)
- [SOC Investigation — Zeek Log Types](https://www.socinvestigation.com/threat-hunting-with-zeek-log-types-and-use-cases/)
- [JA4+ Network Fingerprinting (zeek.org)](https://zeek.org/2026/01/how-to-use-ja4-network-fingerprints-in-zeek/)
