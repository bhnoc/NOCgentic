# PB-10: C2 Framework Detection

**ATT&CK**: T1071 (Application Layer Protocol), T1132 (Data Encoding), T1573 (Encrypted Channel)
**Data Sources**: Zeek ssl.log, http.log, conn.log, dns.log; Suricata tls/alert events; PCAP
**Tools**: RITA, JA4+, JARM, C2-Profiler, tshark, Wireshark

## Overview

Modern C2 frameworks are designed to blend into legitimate network traffic. Detection requires fingerprinting their TLS configuration, behavioral patterns, and HTTP characteristics rather than relying purely on signatures.

---

## Cobalt Strike

### Default Network Fingerprints

| Fingerprint Type | Value |
|-----------------|-------|
| JA3 (client, default) | `a0e9f5d64349fb13191bc781f81f42e1` |
| JA3 (alternate) | `72a589da586844d7f0818ce684948eea` |
| JARM (default) | `07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1` |
| Default TLS CN | `Major Cobalt Strike` |
| Default cert serial | Known bad serial numbers (varies by version) |

### Detection Queries

```bash
# Zeek: hunt known Cobalt Strike JA3 hashes
zeek-cut ts id.orig_h id.resp_h id.resp_p ja3 < ssl.log | \
  grep -E 'a0e9f5d64349fb13191bc781f81f42e1|72a589da586844d7f0818ce684948eea'

# Zeek: hunt default CS TLS cert
zeek-cut ts id.orig_h id.resp_h subject < ssl.log | grep -i "cobalt strike"

# Suricata rule
alert tls any any -> any any (
  msg:"Cobalt Strike Default TLS Certificate";
  tls.cert_subject; content:"CN=Major Cobalt Strike";
  sid:9000001; rev:1;)

# Behavioral: CS beacons with ~60 second intervals (default sleep)
# → Use RITA beaconing detection (score near 1.0 for 60s interval pairs)
```

### Malleable C2 HTTP Patterns

```bash
# Cobalt Strike's malleable C2 profiles customize HTTP headers and URIs
# Look for unusual combinations of:
# - HTTP methods (GET/POST to non-standard URIs)
# - Host headers that don't match expected services
# - CS default URIs: /updates.rss, /jquery-3.3.1.min.js, /pixel.gif, /push

zeek-cut ts id.orig_h host uri user_agent method < http.log | \
  awk -F'\t' '$3 ~ /updates\.rss|jquery-3\.3\.1\.min\.js|pixel\.gif|ca\.gif/'

# Check for CS default checksum8 URLs (GET /[a-z]{4,5})
zeek-cut ts id.orig_h host uri < http.log | \
  awk -F'\t' '$3 ~ /^\/[a-z]{4,6}$/' | sort | uniq -c | sort -rn
```

---

## Sliver

### Network Fingerprints

| Fingerprint | Value | Notes |
|-------------|-------|-------|
| JA3 (Go TLS default) | Varies by Go version; Golang cipher suites | Go TLS stack is distinctive |
| JARM | Varies; Go TLS server fingerprint | Can be randomized by attacker |
| HASSH | Sliver SSH operator channel fingerprint | Available in ssh.log |
| Protocols | mTLS, HTTP, HTTPS, DNS, WireGuard | Multiple C2 channels |

```bash
# Sliver uses Go's TLS library — Golang TLS has distinctive cipher suite ordering
# Hunt for Go TLS client fingerprints
zeek-cut ts id.orig_h id.resp_h ja3 < ssl.log | \
  awk -F'\t' '{
    # Go TLS JA3 patterns include specific cipher suite ordering
    # Common Go JA3: starts with 771, then specific cipher list
    if ($4 ~ /^771,/) {
      # Could be Go-based tool — investigate further
      print
    }
  }' | sort | uniq | head -20

# mTLS (mutual TLS) — both client and server present certs
# Hunt for connections where client cert is presented (unusual for browsers)
tshark -r cap.pcap -Y 'tls.handshake.type == 11' -T fields \
  -e ip.src -e ip.dst -e tls.handshake.certificate

# Sliver DNS C2 — DNS over HTTPS or DNS TXT record beaconing
zeek-cut id.orig_h qtype_name query < dns.log | \
  awk -F'\t' '$2=="TXT"' | sort | uniq -c | sort -rn
```

---

## Metasploit / Meterpreter

```bash
# Default Metasploit TLS certificate CN
zeek-cut ts id.orig_h id.resp_h subject < ssl.log | \
  grep -i "MetasploitSelfSignedCA\|msf4\|msf5"

# Known Metasploit JA3
zeek-cut ts id.orig_h id.resp_h ja3 < ssl.log | \
  grep -E 'e7d705a3286e19ea42f587b07663469e|6734f37431670b3ab4292b8f60f29984'

# Meterpreter reverse TCP pattern: connection to high port, persistent, small keepalives
zeek-cut id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes < conn.log | \
  awk -F'\t' '$3 > 1024 && $3 < 65535 && $4 > 3600 && $5 < 1000' | head -20
```

---

## Havoc

```bash
# Havoc uses a custom protocol over HTTP/HTTPS
# Fingerprints differ from CS and Sliver

# Hunt for Havoc agent characteristics:
# - HTTP POST to /demon/connect or similar paths
# - Specific User-Agent patterns
# - AES-256-CBC encrypted body (look for high entropy POST bodies)

zeek-cut host uri method user_agent < http.log | \
  awk -F'\t' '$3=="POST" && $2 ~ /demon|connect|register/' | sort | uniq

# Suricata rule for Havoc HTTP patterns
# alert http any any -> any any (
#   msg:"Possible Havoc C2 Registration";
#   http.method; content:"POST";
#   http.uri; content:"/demon/";
#   sid:9000010; rev:1;)
```

---

## Brute Ratel C4

```bash
# Brute Ratel uses HTTP/HTTPS with unique User-Agent strings and header patterns
# JA3 fingerprint depends on configuration

# Hunt for known Brute Ratel default behaviors:
# - POST to /tasks, /result, /files endpoints
# - Custom User-Agent headers mimicking legitimate software
# - Certificate subjects like "Brute Ratel C4"

zeek-cut ts id.orig_h host uri subject < ssl.log | \
  grep -i "brute ratel"

# HTTP pattern
zeek-cut host uri method user_agent < http.log | \
  awk -F'\t' '$3=="POST" && ($2 ~ /\/tasks|\/result|\/files/)' | sort | uniq
```

---

## Mythic Framework

```bash
# Mythic (formerly Apfell) supports multiple agents and protocols
# Detection depends on which agent profile is in use

# Common detection: C2 profile-specific URL patterns or headers
# Hunt for unusual HTTPS POST patterns to non-CDN IPs

zeek-cut id.orig_h id.resp_h id.resp_p method status_code < http.log | \
  awk -F'\t' '$4=="POST" && $5 ~ /200|201/' | \
  awk -F'\t' '$2 !~ /^10\.|^172\.|^192\.168\./' | sort | uniq -c | sort -rn
```

---

## C2-Profiler Tool (Automated Detection)

```bash
# C2-Profiler identifies framework from PCAP
# GitHub: mazen91111/C2-Profiler

# Input: PCAP or Zeek conn.log
# Analyzes: beacon intervals, URI patterns, JA3, HTTP headers
# Identifies: Cobalt Strike, Metasploit, Sliver, Havoc, Covenant, Brute Ratel

python c2-profiler.py --pcap capture.pcap --output results.json
python c2-profiler.py --zeek-logs /path/to/zeek/logs/ --output results.json
```

---

## Generic C2 Detection Heuristics

Apply when no specific framework is identified:

```bash
# 1. Long-duration connections on port 80/443 (hours+) — unusual for web browsing
zeek-cut id.orig_h id.resp_h id.resp_p duration service < conn.log | \
  awk -F'\t' '($3==80 || $3==443) && $4+0 > 3600' | sort -k4 -rn | head -10

# 2. Low data volume but many connections (heartbeat pattern)
zeek-cut id.orig_h id.resp_h orig_bytes resp_bytes < conn.log | \
  awk -F'\t' '$3+0 < 500 && $4+0 < 500' | sort | uniq -c | sort -rn | head -20

# 3. HTTPS to IP (no domain name) — C2 to raw IP
zeek-cut id.orig_h id.resp_h server_name < ssl.log | \
  awk -F'\t' '$3 == "" || $3 == "-"' | \
  awk -F'\t' '$2 !~ /^10\.|^172\.|^192\.168\./' | sort | uniq -c | sort -rn

# 4. Non-browser User-Agents making structured HTTP requests
zeek-cut id.orig_h host user_agent < http.log | \
  awk -F'\t' '$3 !~ /Mozilla|Chrome|Safari|Firefox|Edge|Opera/' | \
  sort | uniq -c | sort -rn | head -20

# 5. First-time external connections (new destination not seen before)
# Requires baseline of known-good destinations
```

---

## Suricata Rules for C2 Detection

```bash
# Enable ET rules that cover C2 patterns
# category: et/malware, et/trojan, et/current_events

# Custom rule: HTTP C2 with no referrer and suspicious pattern
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"Possible HTTP C2 — No Referer, POST with small body";
  http.method; content:"POST";
  flow:established,to_server;
  http.header; content:!"Referer";
  dsize:<500;
  threshold: type limit, track by_src, count 5, seconds 60;
  sid:9000020; rev:1;)
```

---

## Response

1. Confirm C2 by full PCAP analysis of implicated sessions
2. Identify all hosts communicating with the same dst IP
3. Timeline reconstruction: initial access → persistence → C2 establishment
4. Block C2 infrastructure at network level
5. Identify and eradicate implant from all affected hosts
6. Check for lateral movement during C2 active period (see [PB-03](./PB-03-lateral-movement.md))

## Sources

- [Cobalt Strike Defense Guide — DFIR Report](https://thedfirreport.com/2022/01/24/cobalt-strike-a-defenders-guide-part-2/)
- [Cobalt Strike Detection Playbook — Hive Security](https://hivesecurity.gitlab.io/blog/cobalt-strike-detection-hunting/)
- [Sliver C2 Detection — Corelight](https://corelight.com/blog/new-sliver-c2-detection-released-redteam-detected/)
- [Dissecting JA4H for Sliver Detections (webscout.io)](https://blog.webscout.io/dissecting-ja4h-for-improved-sliver-c2-detections/)
- [C2-Profiler GitHub](https://github.com/mazen91111/C2-Profiler)
- [Modular C2 Frameworks 2025 (alphahunt.io)](https://blog.alphahunt.io/modular-c2-frameworks-quietly-redefine-threat-operations-for-2025-2026/)
- [Detection of C2 Using Suricata (cyber.wtf)](https://cyber.wtf/2024/12/06/detection-of-c2-using-suricata/)
