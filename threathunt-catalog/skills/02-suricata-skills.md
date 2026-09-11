# Suricata Skills

## Log Types (Data Sources — eve.json subtypes)

Suricata outputs a single `eve.json` stream; each record has an `event_type` field.

| event_type | Contents | Primary Hunt Use |
|------------|----------|------------------|
| `alert` | IDS rule match: rule metadata, sid, category, severity | Known-bad signature hits, rule-based detection |
| `flow` | Flow record: 5-tuple, bytes, packet counts, timing | Baseline deviation, volume anomalies, exfiltration |
| `http` | Full HTTP transaction: URI, method, status, UA, referrer, content-type | Malware download, C2 HTTP, UA hunting |
| `dns` | DNS query/response pairs, rrtype, rcode | DGA, DNS tunneling, C2 domain resolution |
| `tls` | TLS handshake: version, JA3/JA3S, SNI, cert subject, serial | C2 TLS fingerprinting, cert anomalies |
| `fileinfo` | File metadata: name, hash (MD5/SHA1/SHA256), MIME type, stored | Malware transfer detection, file hash lookup |
| `anomaly` | Protocol decode errors and RFC violations | Exploit attempts, malformed packet attacks, IDS evasion |
| `smb` | SMB protocol details: command, tree, file, status | Lateral movement, EternalBlue, PsExec, ransomware |
| `ssh` | SSH connection metadata, auth method, HASSH fingerprint | Brute force, lateral movement via SSH |
| `krb5` | Kerberos protocol records, ticket types, encryption types | Kerberoasting, ticket attacks |
| `rdp` | RDP session details, negotiation flags | Lateral movement, RDP spray |
| `ftp` | FTP command/response pairs, file operations | FTP exfiltration, malware staging |
| `smtp` | Email session details, message metadata | Phishing delivery, BEC |
| `nfs` | NFS operations | Unauthorized file system access |
| `tftp` | TFTP transfers | Firmware deployment, lateral staging |
| `dhcp` | DHCP request/ack pairs | Rogue device detection |
| `pkthdr` | Raw packet header for PCAP logging | Evidence collection |
| `stats` | Suricata performance statistics | Rule performance tuning |

## Detection Techniques

### 1. Signature-Based Detection (Alerting Mode)
- Apply curated rulesets to traffic; review `alert` events for known-bad patterns
- Tune rules with threshold/suppress to reduce false positives before hunting

### 2. Protocol Log Hunting Without Alerts
- Query `http`, `dns`, `tls`, `smb` event types directly — Suricata logs these even with no alert firing
- Find suspicious behavior that no rule yet covers: novel C2, unusual HTTP patterns, first-seen domains
- Example: `jq 'select(.event_type=="http") | select(.http.status==200) | select(.http.http_content_type=="application/octet-stream")' eve.json`

### 3. flow_id Correlation
- Every alert, protocol log, and file event shares the same `flow_id` value for that network flow
- Given an alert, join to `http` or `fileinfo` events with same `flow_id` to get full context
- Example: `jq --arg fid "1234567890" 'select(.flow_id==$fid)' eve.json`

### 4. Flowbits — Multi-Stage Detection Chains
- Rules can `flowbits:set,stagename` on first event then `flowbits:isset,stagename` on subsequent events in same flow
- Example chain: (1) HTTP download of executable → set flowbit `http.exe.download`; (2) subsequent connection from same host → check flowbit → combine into single high-confidence alert
- Sort flows by unique flowbit count to surface the most active/suspicious connections

### 5. File Extraction + YARA Scanning
```yaml
# suricata.yaml file extraction config
file-store:
  enabled: yes
  dir: /var/log/suricata/files
  force-hash: [md5, sha1, sha256]
  force-filestore: yes
```
- Files land in `/var/log/suricata/files/` organized by SHA256
- Run YARA against extracted files: `yara -r malware_rules.yar /var/log/suricata/files/`
- Submit hashes to VirusTotal or internal sandbox

### 6. Executable Download Detection
```bash
# jq filter: HTTP 200 responses with executable MIME types, no referrer
jq 'select(.event_type=="http") |
    select(.http.status==200) |
    select(.http.http_content_type | test("application/octet-stream|application/x-msdownload|application/x-dosexec")) |
    select(.http.http_refer == null or .http.http_refer == "")' eve.json
```

### 7. JA3/JA3S Hunting
```bash
# Find all unique JA3 hashes and their destinations
jq 'select(.event_type=="tls") | {ja3: .tls.ja3.hash, ja3s: .tls.ja3s.hash, dest: .dest_ip}' eve.json | sort -u

# Hunt for known-bad Cobalt Strike JA3
jq 'select(.event_type=="tls") | select(.tls.ja3.hash=="a0e9f5d64349fb13191bc781f81f42e1")' eve.json
```

### 8. Lateral Movement Ruleset Application
- Enable Stamus Open Lateral Movement Ruleset in addition to ET Open
- Watch `smb` event_type for ADMIN$/C$/IPC$ share access patterns
- Correlate with `alert` events from lateral movement rule category

### 9. PAW Patrules Application
- Detects suspicious flows, malicious tool signatures, lateral movement, and bad practices
- Complement to ET rules — focus on behavioral/anomaly detections

### 10. Anomaly Log Hunting
```bash
# Protocol violations may indicate exploit attempts or evasion
jq 'select(.event_type=="anomaly") | {type: .anomaly.type, event: .anomaly.event, layer: .anomaly.layer}' eve.json | sort | uniq -c | sort -rn
```

### 11. Custom Rule Development

**Rule Structure:**
```
action proto src_ip src_port direction dst_ip dst_port (options)
```

**Example — Hunt for Cobalt Strike default certificate:**
```
alert tls any any -> any any (msg:"Possible Cobalt Strike TLS Certificate"; tls.cert_subject; content:"CN=Major Cobalt Strike"; sid:9000001; rev:1;)
```

**Example — Hunt for PowerShell download cradle via HTTP:**
```
alert http any any -> any any (msg:"PowerShell Download Cradle"; http.user_agent; content:"PowerShell"; nocase; http.uri; content:".ps1"; nocase; sid:9000002; rev:1;)
```

**Key Rule Options:**
- `content`, `pcre` — pattern matching
- `http.uri`, `http.header`, `http.user_agent` — HTTP-specific sticky buffers
- `tls.sni`, `tls.cert_subject` — TLS-specific sticky buffers
- `flowbits:set/isset/unset` — state tracking across flow
- `threshold: type limit, track by_src, count 5, seconds 60` — rate limiting
- `detection_filter: track by_src, count 10, seconds 5` — suppress until threshold

### 12. Multi-flowbit Flow Sorting
```bash
# Sort flows by unique flowbits count — highest complexity flows are most interesting
jq 'select(.event_type=="alert") | {flow_id: .flow_id, action: .alert.action, rule: .alert.signature}' eve.json \
  | sort | uniq -c | sort -rn | head -20
```

## Curated Rulesets

| Ruleset | Maintainer | Focus | Cost |
|---------|-----------|-------|------|
| **ET Open** | Proofpoint | Broad malware, exploits, C2, phishing | Free |
| **ET Pro** | Proofpoint | Enhanced + faster updates, more coverage | Paid |
| **Secureworks CTU** | Secureworks | Malware and targeted threat coverage | Free (via ET) |
| **Stamus Open Lateral Movement** | Stamus Networks | Windows LotL and lateral movement techniques | Free |
| **PAW Patrules** | Community | Suspicious flows, bad practices, tool detection | Free |
| **travisbgreen/hunting-rules** | Travis Green | Network anomaly hunting (non-signature) | Free/GitHub |
| **OISF/suricata-update** | OISF | Rule management tool + multiple free sources | Free |
| **Abuse.ch Feodo** | Abuse.ch | Botnet/C2 IP blocklist rules | Free |
| **Stamus Labs TI feeds** | Stamus Networks | TI-backed rules and IOC feeds | Freemium |

## Useful jq Hunting Queries

```bash
# Top destination IPs by flow count
jq -r 'select(.event_type=="flow") | .dest_ip' eve.json | sort | uniq -c | sort -rn | head -20

# HTTP user-agents frequency analysis
jq -r 'select(.event_type=="http") | .http.http_user_agent' eve.json | sort | uniq -c | sort -rn

# DNS queries with NXDomain
jq 'select(.event_type=="dns") | select(.dns.rcode=="NXDOMAIN") | .dns.rrname' eve.json | sort | uniq -c | sort -rn

# All unique TLS SNIs going outbound
jq -r 'select(.event_type=="tls") | .tls.sni' eve.json | sort -u

# Files with PE/executable MIME type
jq 'select(.event_type=="fileinfo") | select(.fileinfo.mimetype | test("application/x-dosexec|application/x-executable"))' eve.json

# Kerberos RC4 (Kerberoasting indicator)
jq 'select(.event_type=="krb5") | select(.krb5.encryption_type=="rc4-hmac")' eve.json

# SMB admin share access
jq 'select(.event_type=="smb") | select(.smb.tree | test("\\\\ADMIN\\$|\\\\C\\$|\\\\IPC\\$"))' eve.json

# Alert summary by signature
jq -r 'select(.event_type=="alert") | .alert.signature' eve.json | sort | uniq -c | sort -rn | head -30

# Protocol anomalies grouped by type
jq -r 'select(.event_type=="anomaly") | .anomaly.type' eve.json | sort | uniq -c | sort -rn
```

## Suricata Resources

- [The Security Analyst's Guide to Suricata](https://www.stamus-networks.com/free-suricata-book) (free book)
- [Suricata Documentation](https://suricata.readthedocs.io/)
- [Suricata Rule Index](https://rules.suricata.io/)
- [Stamus Networks Blog — Suricata Threat Hunting](https://www.stamus-networks.com/blog/suricata-threat-hunting-fundamentals)
- [travisbgreen/hunting-rules](https://github.com/travisbgreen/hunting-rules)
- [SELKS](https://github.com/StamusNetworks/SELKS) — Turnkey Suricata+ELK stack
- [Detection of C2 Using Suricata (cyber.wtf)](https://cyber.wtf/2024/12/06/detection-of-c2-using-suricata/)
