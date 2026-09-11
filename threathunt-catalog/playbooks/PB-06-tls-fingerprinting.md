# PB-06: TLS & Protocol Fingerprinting

**ATT&CK**: T1071.001 (Web Protocols), T1071.002 (File Transfer Protocols), T1021.004 (SSH), T1021.001 (RDP)
**Data Sources**: Zeek ssl.log, ssh.log, rdp.log, http.log, x509.log; Suricata tls events
**Tools**: JA4+ Zeek package, JARM scanner, tshark

## Overview

Network fingerprinting identifies client/server software by the TLS/protocol parameters negotiated — even when traffic is encrypted. These fingerprints remain stable across sessions and are useful for C2 attribution, anomaly detection, and software inventory.

## Fingerprint Family

| Fingerprint | Protocol | Direction | Tool | Stability |
|-------------|---------|-----------|------|-----------|
| **JA3** | TLS | Client hello | Zeek, tshark | Moderate (extension order affects) |
| **JA3S** | TLS | Server hello | Zeek, tshark | Moderate |
| **JA4** | TLS | Client hello | JA4+ Zeek package | High (stable with randomized extensions) |
| **JA4S** | TLS | Server hello | JA4+ Zeek package | High |
| **JA4H** | HTTP | Request | JA4+ Zeek package | High (headers, not body) |
| **JA4SSH** | SSH | Both | JA4+ Zeek package | High |
| **JARM** | TLS (active) | Server | JARM tool | High (server-side config) |
| **HASSH** | SSH | Client | Zeek ssh.log | High |
| **HASSSHServer** | SSH | Server | Zeek ssh.log | High |
| **RDFP** | RDP | Client | Zeek rdp.log | Moderate |
| **Hfinger** | HTTP | Request | Hfinger tool | High |

---

## JA3 / JA3 Hunting

### How JA3 Works
JA3 hashes: SSLVersion + Ciphers + Extensions + EllipticCurves + EllipticCurvePointFormats  
The result is an MD5 hash that identifies the TLS client library regardless of the destination.

### Zeek: Extract JA3 Hashes

```bash
# Install JA3 package (or JA4+ which includes it)
zkg install zeek/salesforce/ja3

# Extract all unique JA3 hashes with their client IPs
zeek-cut id.orig_h ja3 ja3s < ssl.log | sort | uniq -c | sort -rn | head -30

# Find JA3 hashes that appear rarely (potential implants vs common browsers)
zeek-cut ja3 < ssl.log | sort | uniq -c | sort -n | head -20  # Least common first

# Hunt for known-bad Cobalt Strike JA3
zeek-cut ts id.orig_h id.resp_h ja3 ja3s < ssl.log | \
  grep -E 'a0e9f5d64349fb13191bc781f81f42e1|72a589da586844d7f0818ce684948eea'
```

### tshark: JA3 Extraction

```bash
# Extract JA3 from PCAP (requires Wireshark/tshark with ja3 plugin or tls dissector)
tshark -r cap.pcap -Y 'tls.handshake.type == 1' -T fields \
  -e ip.src -e ip.dst -e tls.handshake.ciphersuite \
  -e tls.handshake.extensions_server_name | head -50
```

### Known-Bad JA3 Hashes

```bash
# Create a hunting file with known C2 JA3 hashes
cat > /tmp/bad_ja3.txt << 'EOF'
a0e9f5d64349fb13191bc781f81f42e1  # Cobalt Strike default
72a589da586844d7f0818ce684948eea  # Cobalt Strike alternate
e7d705a3286e19ea42f587b07663469e  # Metasploit
6734f37431670b3ab4292b8f60f29984  # Metasploit alternate
6d8e7a7b5e4a4b2a9f2b2f4b7d4e8b2d  # Sliver Go TLS default
EOF

# Scan ssl.log against list
zeek-cut ts id.orig_h id.resp_h id.resp_p ja3 < ssl.log | \
  while IFS=$'\t' read ts orig resp port ja3; do
    if grep -q "^$ja3" /tmp/bad_ja3.txt; then
      echo "BAD JA3 MATCH: $ts $orig -> $resp:$port JA3=$ja3"
    fi
  done
```

---

## JA4 Hunting (Preferred over JA3)

JA4 is stable even when clients randomize TLS extension ordering (a JA3 evasion technique).

```bash
# Install JA4+ Zeek package
zkg install zeek/foxio/ja4

# After loading, ssl.log will include ja4, ja4s fields
# http.log includes ja4h (HTTP fingerprint)
# ssh.log includes ja4ssh

# Extract JA4 fingerprints
zeek-cut ts id.orig_h id.resp_h ja4 < ssl.log | sort | uniq -c | sort -rn

# Hunt for rare JA4 fingerprints (implants vs common browsers)
zeek-cut ja4 < ssl.log | sort | uniq -c | sort -n | head -30

# Check JA4 fingerprint of known-bad Cobalt Strike
# CS default JA4: t13d190900_9dc949149365_97f8aa674fd9
```

---

## JARM (TLS Server Fingerprinting)

JARM actively probes a server with specially crafted TLS ClientHellos and records how the server responds. This identifies server-side TLS configuration.

```bash
# Run JARM against suspicious IP
python jarm.py 1.2.3.4

# Known-bad JARM hashes
JARM_CS="07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"  # Cobalt Strike
JARM_SLIVER="05d14d16d04d04d05c05d14d04d04d4606ef7946105f20b303b9aef925693"   # Sliver (varies)

# Batch JARM scan of suspicious IPs from conn.log
zeek-cut id.resp_h id.resp_p < ssl.log | sort -u | \
  while IFS=$'\t' read ip port; do
    echo "Scanning $ip:$port"
    python jarm.py "$ip" -p "$port" >> /tmp/jarm_results.txt
  done
```

---

## HASSH (SSH Fingerprinting)

HASSH fingerprints SSH clients and servers based on algorithm negotiation.

```bash
# Zeek ssh.log includes hassh and hassh_server fields
zeek-cut ts id.orig_h id.resp_h hassh hassh_server < ssh.log | sort | uniq -c | sort -rn

# Unusual SSH client libraries (non-OpenSSH)
zeek-cut id.orig_h hassh < ssh.log | \
  awk -F'\t' '$2 != "ec7378c1a92f5a8dde7e8b7a1ddf33d1"' | \
  sort | uniq -c | sort -rn | head -20
# Note: ec7378c1a92f5a8dde7e8b7a1ddf33d1 is standard OpenSSH HASSH
```

---

## TLS Certificate Anomaly Hunting

```bash
# Self-signed certificates (issuer == subject)
zeek-cut ts id.orig_h id.resp_h subject issuer validation_status < ssl.log | \
  awk -F'\t' '$4==$5 || $6=="self signed certificate"' | sort | uniq

# Short-validity certificates (< 30 days — Let's Encrypt automates, malware may misuse)
# Requires x509.log with cert validity dates
zeek-cut ts fingerprint subject not_valid_before not_valid_after < x509.log | \
  awk -F'\t' '{
    # Days of validity
    days = ($5 - $4) / 86400
    if (days < 30 || days > 3650) print days, $1, $2, $3
  }' | sort -rn

# SNI/Subject CN mismatch (suspicious proxy behavior or cert reuse)
zeek-cut ts id.orig_h id.resp_h subject server_name < ssl.log | \
  awk -F'\t' '
    $4 != "" && $5 != "" && $4 !~ $5 {
        print $0
    }' | head -20
```

---

## HTTP Fingerprinting (JA4H / Hfinger)

```bash
# JA4H fingerprints HTTP based on: method, version, headers present/absent, cookie count
# Available in http.log after JA4+ package install
zeek-cut ts id.orig_h id.resp_h ja4h < http.log | sort | uniq -c | sort -rn

# Rare HTTP fingerprints (potential C2 or non-browser tools)
zeek-cut ja4h < http.log | sort | uniq -c | sort -n | head -20

# HTTP headers analysis: spot non-browser request patterns
zeek-cut id.orig_h host uri user_agent < http.log | \
  awk -F'\t' '$4 == "" || $4 ~ /python|curl|wget|Go-http|PowerShell/' | \
  sort | uniq -c | sort -rn | head -20
```

---

## RDFP (RDP Fingerprinting)

```bash
# Zeek rdp.log includes fingerprint field (RDFP)
zeek-cut ts id.orig_h id.resp_h security_protocol cert_subject desktop_width < rdp.log | \
  sort | uniq

# Flag RDP connections using NLA (expected) vs CredSSP downgrade (suspicious)
zeek-cut id.orig_h id.resp_h security_protocol < rdp.log | \
  awk -F'\t' '$3 != "SSL_With_NLA" && $3 != "TLS"' | sort | uniq
```

---

## Operationalizing Fingerprints

```bash
# Build JA3 frequency baseline from known-good traffic
zeek-cut ja3 < ssl.log | sort | uniq -c | sort -rn > /tmp/ja3_baseline.txt

# Feed new traffic through — flag fingerprints absent from baseline
zeek-cut ts id.orig_h id.resp_h ja3 < new_ssl.log | \
  while IFS=$'\t' read ts orig resp ja3; do
    if ! grep -q "$ja3" /tmp/ja3_baseline.txt; then
      echo "NEW JA3: $ts $orig -> $resp $ja3"
    fi
  done
```

## Sources

- [Zeek.org — How to Use JA4 Network Fingerprints](https://zeek.org/2026/01/how-to-use-ja4-network-fingerprints-in-zeek/)
- [JA3 GitHub (Salesforce)](https://github.com/salesforce/ja3)
- [JA4+ GitHub (FoxIO)](https://github.com/FoxIO-LLC/ja4)
- [Passive TLS Fingerprinting with JA3 and JA4 (systemshardening.com)](https://www.systemshardening.com/articles/network/tls-fingerprinting-ja3-ja4/)
- [Awesome Threat Detection — Network Fingerprinting](https://0x4d31.github.io/awesome-threat-detection/)
