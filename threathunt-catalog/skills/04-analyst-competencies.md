# Analyst Competencies

Core skill domains for network threat hunting and PCAP/Zeek/Suricata analysis.

## Technical Skill Domains

### 1. Networking & Protocol Knowledge

| Protocol | What to Know for Hunting |
|----------|--------------------------|
| **TCP/IP** | 3-way handshake, flags (SYN, ACK, FIN, RST, PSH), IPID field, TTL, fragmentation |
| **DNS** | Query types (A, AAAA, MX, TXT, CNAME, PTR, NULL), recursive vs iterative, RCODE values, zone transfer (AXFR) |
| **HTTP/S** | Methods (GET/POST/PUT), status codes, headers (Host, User-Agent, Referer, Authorization), chunked encoding, websockets |
| **TLS** | Handshake phases, cipher suites, certificate structure, SNI, ALPN, session resumption, certificate pinning |
| **Kerberos** | AS-REQ/REP, TGS-REQ/REP, AP-REQ, ticket structure, encryption types (AES vs RC4), PAC |
| **SMB** | SMB1 vs SMB2/3, named pipes (IPC$), share types (disk, printer, IPC), NTLMSSP authentication |
| **NTLM** | Challenge-response, Pass-the-Hash mechanics, NTLMv1 vs NTLMv2, relay attacks |
| **RDP** | RDP protocol versions, NLA authentication, clipboard/drive redirection |
| **SSH** | Key exchange algorithms, HASSH fields, channel types, port forwarding |
| **ICMP** | Type/code meanings, tunneling (ICMP echo payload), ping sweep patterns |
| **NetFlow/IPFIX** | Flow record fields, sampling, limitations vs full PCAP |

### 2. PCAP Analysis Skills
- Wireshark GUI: display filters, protocol decode, expert info, stream follow, IO graphs
- tshark CLI: `-T fields`, `-e`, `-Y`, `-z` statistics, `-r`/`-i` modes, `--export-objects`
- tcpdump: BPF filter syntax, capture and read modes
- Session reconstruction from full PCAP (TCP stream reassembly)
- File carving from network captures
- Correlation of PCAP timestamps with log sources

### 3. Zeek Log Analysis
- Understanding all log types and their schemas
- zeek-cut for field extraction
- Log correlation using `uid` field
- RITA for automated C2/beaconing analysis
- Brim/Zed Lake with ZQL queries
- Zeek scripting for custom detections

### 4. Suricata Analysis
- eve.json schema and event_type navigation
- jq filtering for eve.json analysis
- Rule reading and writing (content, pcre, flowbits, http.*  sticky buffers)
- Ruleset management with suricata-update
- File extraction configuration and workflow

### 5. Query Languages

| Language | Platform | Use |
|----------|----------|-----|
| **KQL** | Microsoft Sentinel, Defender | Azure/M365 environment hunting |
| **SPL** | Splunk | Splunk-based SIEM hunting |
| **Lucene/ES DSL** | Elasticsearch/Kibana | ELK stack queries |
| **ZQL** | Brim/Zed | PCAP + Zeek log queries in Brim |
| **SQL** | Any | General log analysis, osquery |
| **jq** | CLI | JSON log filtering (eve.json, API responses) |
| **awk/grep/sed** | CLI | Text log processing, field extraction |

### 6. Scripting & Automation
- **Python**: pyshark (PCAP parsing), scapy (packet manipulation), pandas (log analytics), requests (API enrichment)
- **Bash**: Log parsing pipelines, IOC sweep scripts, alerting automation
- **PowerShell**: Windows-side forensics, event log querying, Active Directory queries
- **Zeek scripts**: Custom event handlers, policy scripts, detection rules

### 7. Statistics for Anomaly Detection
- Standard deviation calculation (for beaconing jitter analysis)
- Shannon entropy (for DGA domain name analysis)
- Z-score / outlier detection (for traffic volume anomalies)
- Frequency analysis (for user-agent, DNS query, JA3 rarity scoring)
- Clustering concepts (k-means, DBSCAN for behavioral grouping)

### 8. Threat Intelligence
- IOC enrichment workflow (IP, domain, hash, URL)
- Infrastructure pivoting (passive DNS, cert transparency, JARM correlation)
- Threat intelligence platforms: MISP, OpenCTI, MITRE ATT&CK
- Feed formats: STIX 2.1, TAXII 2.1, CSV, JSON
- Confidence scoring and IOC lifecycle management

### 9. Digital Forensics
- Chain of custody and evidence preservation
- Disk imaging and write-blocking concepts
- Memory dump analysis (Volatility) for credential and IOC extraction
- Timeline construction (plaso/log2timeline)
- Artifact correlation: network ↔ endpoint ↔ log

### 10. Cloud Environments
- AWS: VPC Flow Logs, CloudTrail, GuardDuty findings, S3 access logs
- Azure: NSG Flow Logs, Azure Monitor, Defender for Cloud, Sign-in Logs
- GCP: VPC Flow Logs, Cloud Audit Logs, Chronicle
- Kubernetes: API server audit logs, container network policies
- Cloud hunting limitations: no PCAP in cloud-native deployments; metadata-only

## Certifications & Training

### Certifications

| Cert | Issuer | Focus |
|------|--------|-------|
| **GNFA** (GIAC Network Forensic Analyst) | GIAC/SANS | Network forensics, PCAP, threat hunting — covers FOR572 content |
| **GCIA** (GIAC Certified Intrusion Analyst) | GIAC/SANS | IDS/IPS, traffic analysis, Snort/Suricata |
| **GCIH** (GIAC Certified Incident Handler) | GIAC/SANS | Incident response including network evidence |
| **GCFE** (GIAC Certified Forensic Examiner) | GIAC/SANS | Forensics including network artifacts |
| **BTL1/BTL2** | Security Blue Team | SOC analysis and threat hunting |
| **CCD** | CyberDefenders | Practical SOC skills |
| **CEH** | EC-Council | Broad security including network analysis |

### Key Courses

| Course | Provider | Content |
|--------|----------|---------|
| **FOR572** | SANS | Advanced Network Forensics — 6 days, 18 labs, NetFlow, PCAP, SSL decrypt, file extraction |
| **FOR508** | SANS | Advanced Incident Response — DFIR with network correlation |
| **SEC503** | SANS | Intrusion Detection In-Depth (GCIA) — Snort/Suricata, PCAP |
| **Zeek Training** | Corelight/Applied Network Defense | Zeek deployment and scripting |
| **Network Forensics** | Antisyphon Training | Practical network forensics with Troy Wojewoda |
| **Suricata for IR & Hunting** | Kaspersky XTraining | Suricata hands-on |
| **HackTheBox Academy** | HTB | RITA for C2 hunting, network modules |
| **TryHackMe** | THM | Zeek, Wireshark, Network Miner rooms |
| **LetsDefend** | LetsDefend | SOC analyst labs including network |
| **CyberDefenders** | CyberDefenders | PCAP analysis challenges and labs |

### Books & Reference Guides

- *The Security Analyst's Guide to Suricata* (Stamus Networks) — free
- *Applied Network Defense* training materials
- *Huntpedia* (Sqrrl) — threat hunting compendium
- *Hunt Evil* (SANS) — practical threat hunting guide
- *The Hunter's Handbook* (Endgame) — threat hunting process
- *Network Forensics: Tracking Hackers Through Cyberspace* (Sherri Davidoff)
- *The Practice of Network Security Monitoring* (Richard Bejtlich)

## Hunt Process Skills

### Hypothesis Formulation
- Translate threat intelligence into testable hunt hypotheses
- Map ATT&CK techniques to available data sources
- Prioritize hunts by: likelihood of occurrence, business impact, data availability
- Document hypothesis, expected evidence, negative cases

### Data Source Mapping
Know which log answers which question:

| Question | Primary Source | Secondary Source |
|----------|---------------|-----------------|
| "Is there beaconing?" | Zeek conn.log + RITA | Suricata flow events + NetFlow |
| "Is there DGA activity?" | Zeek dns.log | Suricata dns events |
| "What files were transferred?" | Zeek files.log | Suricata fileinfo events |
| "Is there lateral movement?" | Zeek smb_mapping.log + kerberos.log | Suricata smb events, PCAP |
| "What's the full session?" | PCAP (raw) | Zeek (structured) |
| "Is a known tool being used?" | Suricata alert events | Zeek notice.log |

### Hunt Execution
1. Write targeted query against primary data source
2. Apply frequency/rarity analysis to narrow to anomalies
3. Pivot on suspicious findings to corroborate
4. Map confirmed findings to ATT&CK technique(s)
5. Escalate to IR or document as low-risk finding

### Operationalizing Hunts
- Convert successful manual hunt into detection rule (Sigma → SIEM, Suricata rule, Zeek script)
- Document false positive exclusions and tuning rationale
- Set metric baseline so rule efficacy is measurable
- Schedule recurring automated run of repeatable hunt queries

## Performance Metrics

| Metric | What It Measures |
|--------|-----------------|
| Dwell time reduction | Time from attacker entry to detection |
| Hunts per quarter | Hunt program velocity |
| New detections created | Operationalization rate |
| False positive rate | Detection quality |
| ATT&CK coverage % | Detection completeness against framework |
| Mean time to hunt (MTTH) | Operational efficiency |
