# Zeek Skills

## Log Types (Data Sources)

| Log | Contents | Primary Hunt Use |
|-----|----------|------------------|
| `conn.log` | All connections: src/dst IP, port, proto, duration, bytes | Port scans, beaconing, exfiltration volume, internal recon |
| `dns.log` | DNS queries, responses, answer RRs, TTLs | DGA detection, DNS tunneling, C2 domain queries, fast flux |
| `http.log` | Hostname, URI, method, status, user-agent, referrer | Malware download, C2 HTTP, suspicious URIs, UA hunting |
| `ssl.log` | TLS version, cipher, cert issuer/subject, JA3/JA4, SNI | Encrypted C2 fingerprinting, cert anomalies, self-signed certs |
| `files.log` | File transfers, MD5/SHA1/SHA256 hashes, MIME types | Malware staging, file exfiltration, malicious document delivery |
| `notice.log` | Security-relevant events flagged by Zeek scripts | Alert triage, policy violations, anomaly flags |
| `kerberos.log` | Kerberos request/response, ticket types, service SPNs | Golden/Silver Ticket, Kerberoasting, AS-REP Roasting |
| `smtp.log` | Email headers, attachment info, relay path | Phishing delivery, BEC, malware distribution via email |
| `ftp.log` | FTP command/response sequences, file transfers | Data exfiltration via FTP, malware staging via FTP |
| `ssh.log` | SSH auth results, algorithm negotiation, HASSH fingerprint | Brute force, lateral movement via SSH, ssh tunneling |
| `rdp.log` | RDP connection metadata, RDFP fingerprint, cert info | Lateral movement via RDP, RDP spray attacks |
| `smb_files.log` | SMB file access events (create, read, write, delete) | Ransomware file encryption, lateral movement staging |
| `smb_mapping.log` | SMB share access and mapping | Admin share access (C$, ADMIN$, IPC$), PsExec detection |
| `tunnel.log` | Detected tunneled traffic (GRE, VXLAN, SOCKS, etc.) | Covert channels, traffic encapsulation |
| `weird.log` | Protocol violations and parsing anomalies | Malformed packet attacks, exploitation attempts, evasion |
| `x509.log` | Certificate chains and extensions | Self-signed cert detection, cert pivoting, JARM correlation |
| `pe.log` | Portable executable metadata from file transfers | Malware download characterization |
| `dpd.log` | Dynamic Protocol Detection — protocol on non-standard port | Port-knocking evasion, tunneling on 80/443 |
| `ntp.log` | NTP protocol data | NTP amplification, unusual NTP talkers |
| `radius.log` | RADIUS authentication records | VPN auth anomalies, credential stuffing |
| `snmp.log` | SNMP community strings and OID requests | Unauthorized network enumeration |
| `software.log` | Software versions detected on the network | Vulnerable software identification, asset inventory |
| `dhcp.log` | DHCP request/response pairs | Rogue device detection, IP-to-hostname mapping |
| `dce_rpc.log` | DCE/RPC protocol calls | WMI-based lateral movement, DCOM abuse |
| `ntlm.log` | NTLM authentication exchanges | Pass-the-Hash, NTLM relay, credential capture |

## Detection Techniques

### 1. Beaconing Detection
- **Data**: `conn.log` — `ts`, `id.orig_h`, `id.resp_h`, `id.resp_p`, `duration`, `orig_bytes`
- **Method**: Calculate standard deviation of connection intervals per (src, dst) pair; low stddev + high frequency = beacon candidate
- **Tool**: RITA (automated), or manual with Python pandas on exported conn.log
- **Signal**: Connections every ~N seconds with low jitter, same small byte sizes

### 2. DGA Domain Detection
- **Data**: `dns.log` — `query`, `qtype`, `rcode`
- **Method**: Calculate domain name entropy (`-sum(p*log(p))`); flag entropy > 3.5 for domains with no prior history; hunt NXDomain burst (RCODE 3 storm)
- **Signal**: High-entropy labels, no vowels, random-looking strings, queried once then never again

### 3. DNS Tunneling Detection
- **Data**: `dns.log` — `query`, `qtype_name`, `answers`, `rejected`
- **Method**: Flag: subdomain length > 50 chars; TXT or NULL query types from workstations; high volume of unique subdomains to single parent domain; unusually large response payloads
- **Signal**: Query like `d2hvYW1pLml0aGluay5pZW5s.evil.com` with TXT response containing encoded data

### 4. Lateral Movement Tracking
- **Data**: `conn.log`, `smb_mapping.log`, `smb_files.log`, `kerberos.log`, `ntlm.log`
- **Method**: Correlate workstation→workstation SMB connections; flag ADMIN$/C$ share access; track Kerberos TGT usage crossing host boundaries in short windows
- **Signal**: Workstation connecting to workstation on 445; service creation via IPC$; NTLM auth from unexpected src

### 5. Data Exfiltration Detection
- **Data**: `conn.log`, `files.log`, `http.log`
- **Method**: Flag `orig_bytes >> resp_bytes` (high outbound ratio); unusual dst ASNs; off-hours transfers; large file transfers to cloud storage domains; ZIP/RAR archives sent outbound
- **Signal**: Single connection with > 100MB outbound to external IP, especially at odd hours

### 6. C2 Certificate Anomaly Hunting
- **Data**: `ssl.log`, `x509.log`
- **Method**: Flag self-signed certs (`issuer == subject`); certs with validity < 90 days or > 2 years; SNI/CN mismatch; cert subjects with random-looking CN; cross-reference JA3/JARM against known-bad lists
- **Signal**: `CN=localhost` or `CN=<random>` on external IPs; cert chain depth of 1 (no intermediate CA)

### 7. Brute Force Detection
- **Data**: `ssh.log`, `kerberos.log`, `ftp.log`, `http.log`
- **Method**: Count failed auth attempts per src IP within rolling window; threshold alert on > N failures in < T minutes
- **Signal**: `auth_attempts > 20` in ssh.log in 60 seconds from same src; RCODE 6 (KRB_AP_ERR_MODIFIED) burst in kerberos.log

### 8. Port/Host Scan Detection
- **Data**: `conn.log`
- **Method**: Count unique `id.resp_h` or `id.resp_p` per `id.orig_h` within short window; flag high unique dst count
- **Signal**: Single src IP touching 100+ unique dst ports or 50+ unique dst hosts in 60 seconds

### 9. Kerberoasting Detection
- **Data**: `kerberos.log`
- **Method**: Flag TGS-REQ (request_type == "TGS") with `request_type` for service accounts using RC4 encryption (etype 23); normal modern Kerberos uses AES (etype 17/18)
- **Signal**: `kerberos.log` shows `cipher == "rc4-hmac"` for service account TGS requests

### 10. Golden Ticket Detection
- **Data**: `kerberos.log`
- **Method**: Flag an `auth_ticket` type entry where there is no preceding `new_ticket` from the KDC for the same client; anomalously long ticket lifetimes (Golden Tickets can be set to 10+ year validity)
- **Signal**: TGT used in service requests but no corresponding AS-REP seen from DC

### 11. UID-Based Session Correlation
- **Data**: All logs — `uid` field is the session identifier consistent across `conn`, `http`, `files`, `ssl`
- **Method**: Given a suspicious `uid` from any log, pivot to all other logs with same `uid` to reconstruct full session
- **Tool**: `zcat *.log.gz | zeek-cut uid ... | grep <target-uid>`; Brim ZQL: `uid == "CHhAvVGS1DHFjwGM9"`

### 12. IoT/OT Device Baselining
- **Data**: `conn.log`, `dhcp.log`, `software.log`
- **Method**: Build per-MAC-address connection profile (dst IPs, ports, protocols); flag first-time destinations or protocols outside baseline
- **Signal**: Smart camera connecting to unexpected cloud region; ICS device making DNS queries it never has before

### 13. AS-REP Roasting Detection
- **Data**: `kerberos.log`
- **Method**: Flag AS-REQ without pre-authentication (`PA-DATA` absent); indicates account with "Do not require Kerberos preauthentication" — attacker can request TGT and crack offline
- **Signal**: Multiple AS-REQ for different accounts without PA-DATA, all from same src IP

## Key Zeek Packages & Scripts

| Package | Function |
|---------|----------|
| **JA4+** | Adds JA4/JA4S/JA4H/JA4SSH fingerprints to ssl.log and http.log |
| **zeek-EternalSafety** | Detects EternalBlue/SMB exploit attempts |
| **Zeek-agent** | Host activity monitoring integrated into Zeek event framework |
| **Loginsoft-Research/zeek-scripts** | CVE detection and threat hunt scripts |
| **Canon88/zeek-threathunting** | Intel framework integration with Kafka for threat hunting |
| **zeek/community-id** | Adds Community ID flow hash for cross-tool correlation |

## Common Zeek CLI Commands

```bash
# Convert PCAP to Zeek logs
zeek -r capture.pcap

# Apply local scripts while reading PCAP
zeek -r capture.pcap local

# Extract specific fields from conn.log
zeek-cut id.orig_h id.resp_h id.resp_p proto orig_bytes resp_bytes < conn.log | head -50

# Find top talkers (bytes out)
zeek-cut id.orig_h orig_bytes < conn.log | sort -t$'\t' -k2 -rn | head -20

# Find all connections to a specific IP
zeek-cut ts id.orig_h id.resp_h id.resp_p < conn.log | awk -F'\t' '$3 == "1.2.3.4"'

# Hunt for NXDomain burst
zeek-cut id.orig_h query rcode_name < dns.log | awk -F'\t' '$3 == "NXDOMAIN"' | sort | uniq -c | sort -rn | head -20

# Find HTTP downloads (non-200 filtered out)
zeek-cut ts host uri resp_mime_types status_code < http.log | awk -F'\t' '$5 == "200"' | grep -E 'exe|dll|ps1|bat'

# Extract unique JA3 hashes
zeek-cut id.orig_h id.resp_h ja3 < ssl.log | sort -u

# Find self-signed certificates
zeek-cut id.resp_h cert_chain_fps validation_status < ssl.log | grep self-signed
```

## Resources

- [Zeek Documentation](https://docs.zeek.org/)
- [Book of Zeek](https://docs.zeek.org/en/master/scripting/index.html)
- [Zeek Package Manager](https://packages.zeek.org/)
- [SOC Investigation — Zeek Log Types and Use Cases](https://www.socinvestigation.com/threat-hunting-with-zeek-log-types-and-use-cases/)
- [Active Countermeasures — Zeek and RITA](https://www.activecountermeasures.com/threat-hunting-over-the-network-with-zeek-and-rita/)
- [RITA GitHub](https://github.com/activecm/rita)
- [TryHackMe Zeek module](https://tryhackme.com/room/zeekbro)
