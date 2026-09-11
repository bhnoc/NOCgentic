# PB-14: Protocol Anomaly & Weird Traffic Detection

**ATT&CK**: T1599 (Network Boundary Bridging), T1572 (Protocol Tunneling), T1001 (Data Obfuscation)
**Data Sources**: Zeek weird.log, conn.log, tunnel.log, dpd.log; Suricata anomaly events; PCAP
**Tools**: Zeek, Suricata, tshark, Wireshark

## Overview

Protocol anomalies indicate protocol misuse, exploitation attempts, evasion techniques, or malformed traffic. Zeek's `weird.log` and Suricata's `anomaly` events capture these without requiring specific signatures.

---

## Zeek weird.log Hunting

```bash
# Top weird events by frequency (most common = likely legitimate; focus on rare)
zeek-cut ts id.orig_h id.resp_h name addl < weird.log | \
  awk -F'\t' '{print $4}' | sort | uniq -c | sort -rn | head -30

# Focus on rare weird events (seen < 5 times = interesting)
zeek-cut name < weird.log | sort | uniq -c | sort -n | head -30

# Filter to external traffic only
zeek-cut ts id.orig_h id.resp_h name < weird.log | \
  awk -F'\t' '$3 !~ /^10\.|^172\.|^192\.168\./' | sort | uniq -c | sort -rn | head -20
```

### Key Weird Event Names to Hunt

| Event | Meaning |
|-------|---------|
| `bad_TCP_checksum` | Possible evasion; IDS-evading split handshake |
| `TCP_ack_underflow_or_misorder` | Likely TCP evasion technique |
| `above_hole_data_without_any_acks` | TCP desynchronization (IDS evasion) |
| `DNS_AAAA_neg_length` | Malformed DNS response (exploit or scanner) |
| `HTTP_version_mismatch` | Protocol downgrade or exploitation attempt |
| `bad_HTTP_reply` | Malformed HTTP response (server-side vulnerability) |
| `connection_originator_SYN_ack` | SYN/ACK as first packet (SYN-ACK scanning) |
| `excess_RPC` | RPC abuse |
| `FTP_command_on_data_channel` | FTP command injection |
| `MIME_base64_bad_char` | Malformed MIME encoding (email exploit) |
| `partial_slip` | SLIP protocol anomaly |
| `SMB_parsing_error` | SMB exploit attempt (EternalBlue precursor) |
| `TCP_Christmas_tree_packet` | Xmas scan (all TCP flags set) |
| `unbalanced_HTTP_request_pipelining` | HTTP request smuggling indicator |

---

## Protocol on Non-Standard Port (DPD)

Zeek's Dynamic Protocol Detection (`dpd.log`) detects when a known protocol runs on a non-standard port.

```bash
# List protocols detected on non-standard ports
zeek-cut ts id.orig_h id.resp_h proto failed < dpd.log | sort | uniq -c | sort -rn

# Examples of suspicious DPD events:
# - SSH on port 443 (attacker hiding C2 as HTTPS)
# - HTTP on port 8443 (HTTPS port used unencrypted)
# - DNS on high port (DNS tunneling)
# - SMB on non-standard port (lateral movement evasion)
```

---

## Tunnel Detection

```bash
# Zeek tunnel.log captures tunneled protocols
zeek-cut ts id.orig_h id.resp_h tunnel_type action < tunnel.log | sort | uniq -c | sort -rn

# Common tunnels of interest:
# - ICMP tunneling (ping with payload)
# - GRE (generic routing encapsulation - could be VPN or exfil)
# - IP-over-DNS (DNS tunneling)
# - SSL/TLS over non-443 (C2 over unusual ports)

# ICMP tunnel detection
tshark -r cap.pcap -Y 'icmp and data.len > 100' -T fields \
  -e ip.src -e ip.dst -e icmp.type -e data.len | sort | uniq -c | sort -rn

# tshark: Detect IP-in-IP or GRE tunneling
tshark -r cap.pcap -Y 'ip.proto == 47 or ip.proto == 4' -T fields \
  -e ip.src -e ip.dst -e ip.proto | sort | uniq -c | sort -rn
```

---

## HTTP Request Smuggling Detection

```bash
# HTTP request smuggling abuses Content-Length + Transfer-Encoding header ambiguity
# Zeek weird.log: look for "unbalanced_HTTP_request_pipelining" or "HTTP_chunked_violations"

# tshark: Flag HTTP requests with both Content-Length and Transfer-Encoding
tshark -r cap.pcap -Y 'http.request and http.transfer_encoding and http.content_length' \
  -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri | head -10
```

---

## SMB Exploit Detection

```bash
# Zeek weird.log SMB parsing errors may indicate EternalBlue/EternalRomance
zeek-cut ts id.orig_h id.resp_h name < weird.log | \
  awk -F'\t' '$4 ~ /SMB/' | sort | uniq -c | sort -rn

# Suricata rules for EternalBlue
grep -i "eternal\|ms17-010\|SMB.*exploit" /etc/suricata/rules/*.rules | head -10

# Network indicator: SMB connection followed by service creation
# → correlate smb_mapping.log (ADMIN$ access) + conn.log (port 445) time correlation
```

---

## Suricata Anomaly Event Hunting

```bash
# Suricata anomaly events (event_type: anomaly)
jq -r 'select(.event_type=="anomaly") | [.anomaly.type, .anomaly.event, .src_ip, .dest_ip] | @tsv' \
  eve.json | sort | uniq -c | sort -rn | head -30

# Anomaly types to focus on:
# applayer_anomaly_detect_error - protocol decode failure (exploit attempt)
# applayer_detect_protocol_only_one_direction - unusual one-sided protocol
# stream_type - TCP stream inconsistency
# decode - packet decode error

# Cross-reference anomaly src with other high-risk activity
SUSPECT_IP="10.0.0.100"
jq --arg ip "$SUSPECT_IP" 'select(.src_ip == $ip)' eve.json | head -50
```

---

## IPv6 Anomaly Hunting

```bash
# Unusual IPv6 traffic in IPv4-only environments
tshark -r cap.pcap -Y 'ipv6' -T fields -e ipv6.src -e ipv6.dst -e ipv6.nxt | \
  sort | uniq -c | sort -rn | head -20

# 6to4 or Teredo tunneling (IPv6 over IPv4 — potential evasion)
tshark -r cap.pcap -Y 'ip.proto == 41' -T fields -e ip.src -e ip.dst | \
  sort | uniq -c | sort -rn | head -10
```

---

## Operating System Fingerprinting (for Asset Discovery)

```bash
# Zeek identifies OS from TCP behavior in conn.log
# Passive OS fingerprinting from TCP options (Zeek uses p0f internally)

# Hunt for unknown/unexpected OS types on specific segments
zeek-cut id.orig_h history < conn.log | sort | uniq | head -20
# Analyze TCP history flags for OS fingerprinting clues

# tshark TTL-based rough OS fingerprinting:
# Linux default TTL: 64
# Windows default TTL: 128
# Network devices: 255
tshark -r cap.pcap -T fields -e ip.src -e ip.ttl | \
  awk '$2 == 128 || $2 == 255 {print}' | sort | uniq | head -20
```

---

## Operationalizing weird.log

```bash
# Build baseline: collect weird.log events from normal operations over 1 week
cat /var/log/zeek/*/weird.log | zeek-cut name | sort | uniq -c | sort -rn > baseline_weird.txt

# Compare new traffic — flag new weird event types not in baseline
cat new_weird.log | zeek-cut ts id.orig_h name | \
  while IFS=$'\t' read ts orig name; do
    if ! grep -q "$name" baseline_weird.txt; then
      echo "NEW WEIRD EVENT: $ts $orig $name"
    fi
  done
```

## Sources

- [Zeek Documentation — weird.log](https://docs.zeek.org/en/master/logs/weird.html)
- [Suricata Anomaly Documentation](https://suricata.readthedocs.io/en/latest/rules/app-layer-events.html)
- [Network Threat Detection](https://networkthreatdetection.com/)
