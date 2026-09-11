# MITRE ATT&CK — Network-Observable Indicator Mapping

All 14 ATT&CK tactics with network-level detection logic, data sources, and relevant playbooks.

---

## TA0043 — Reconnaissance

| Technique | Network Indicator | Zeek/Suricata Source | Playbook |
|-----------|-----------------|---------------------|---------|
| T1595 Active Scanning | Port scan: single src → many dst ports | conn.log: high unique resp_p per orig_h | PB-12 |
| T1590 Gather Victim Network Info | WHOIS/RDAP queries to RIR services | dns.log + http.log | - |
| T1596 Search Open Technical Databases | Queries to Shodan, Censys-like services | http.log: known scanner API endpoints | - |
| T1598 Phishing for Information | Suspicious email with tracking pixel | smtp.log + http.log | - |

---

## TA0042 — Resource Development

| Technique | Network Indicator | Zeek/Suricata Source | Playbook |
|-----------|-----------------|---------------------|---------|
| T1583 Acquire Infrastructure | External (not visible until used) | - | - |
| T1584 Compromise Infrastructure | (External) | - | - |
| T1587 Develop Capabilities | Domain registration before attack | Passive DNS history (enrichment) | PB-08 |
| T1568 Dynamic Resolution (DGA) | High-entropy domain queries, NXDomain burst | dns.log | PB-02 |

---

## TA0001 — Initial Access

| Technique | Network Indicator | Zeek/Suricata Source | Playbook |
|-----------|-----------------|---------------------|---------|
| T1566.001 Phishing: Spearphishing Attachment | Email with malicious attachment delivered | smtp.log, files.log | PB-07 |
| T1566.002 Phishing: Spearphishing Link | Email with URL → malicious download | smtp.log + http.log | PB-07 |
| T1190 Exploit Public-Facing Application | Exploitation traffic, anomalous HTTP responses | weird.log, http.log | PB-14 |
| T1133 External Remote Services | VPN or RDP from unexpected external IP | conn.log, rdp.log | PB-03 |
| T1195 Supply Chain Compromise | Malicious update served over HTTP | http.log: update domain + PE file download | PB-07 |
| T1078 Valid Accounts | Successful auth from unusual geo/IP | kerberos.log, ntlm.log | PB-05 |

---

## TA0002 — Execution

| Technique | Network Indicator | Zeek/Suricata Source | Playbook |
|-----------|-----------------|---------------------|---------|
| T1059 Command and Scripting Interpreter | Script download (PS1, VBS, JS) from HTTP | http.log, files.log | PB-07, PB-13 |
| T1047 WMI Remote Execution | DCE/RPC WMI calls to remote hosts | dce_rpc.log | PB-03 |
| T1059.001 PowerShell | PowerShell UA in http.log; PS1 file download | http.log | PB-13 |
| T1072 Software Deployment Tools | Traffic to deployment server from many hosts | conn.log: fan-out pattern | - |

---

## TA0003 — Persistence

| Technique | Network Indicator | Zeek/Suricata Source | Playbook |
|-----------|-----------------|---------------------|---------|
| T1505.003 Web Shell | HTTP POST with shell-like response patterns | http.log: unusual POST → 200 with output | PB-13 |
| T1197 BITS Jobs | HTTP/HTTPS download activity from BITS | http.log: specific UA patterns | - |
| T1098 Account Manipulation | New account → Kerberos auth activity | kerberos.log | PB-05 |
| T1053.005 Scheduled Task | Remote task creation via SMB/WMI | smb_mapping.log + dce_rpc.log | PB-03 |

---

## TA0004 — Privilege Escalation

| Technique | Network Indicator | Zeek/Suricata Source | Playbook |
|-----------|-----------------|---------------------|---------|
| T1558.003 Kerberoasting | RC4 TGS-REQ for service accounts | kerberos.log: cipher=rc4-hmac | PB-05 |
| T1558.004 AS-REP Roasting | AS-REQ without pre-auth | kerberos.log | PB-05 |
| T1068 Exploitation for Privilege Escalation | Exploit traffic against local service | weird.log | PB-14 |
| T1548 Abuse Elevation Control Mechanism | UAC bypass (endpoint-side; limited network visibility) | - | - |

---

## TA0005 — Defense Evasion

| Technique | Network Indicator | Zeek/Suricata Source | Playbook |
|-----------|-----------------|---------------------|---------|
| T1070 Indicator Removal | (Mostly endpoint; logs deleted) | - | - |
| T1572 Protocol Tunneling | Known protocol inside another (DNS-over-TCP, ICMP tunnel) | tunnel.log, dpd.log | PB-14 |
| T1573 Encrypted Channel | HTTPS/TLS to non-standard destinations | ssl.log: cert anomalies, JA3 | PB-06 |
| T1027 Obfuscated Files | High-entropy POST bodies; encoded URIs | http.log: URI entropy | PB-13 |
| T1036 Masquerading | Malware using browser-like UA; HTTP on 443 without TLS | weird.log + dpd.log | PB-13, PB-14 |

---

## TA0006 — Credential Access

| Technique | Network Indicator | Zeek/Suricata Source | Playbook |
|-----------|-----------------|---------------------|---------|
| T1558 Steal or Forge Kerberos Tickets | Golden/Silver Ticket, Kerberoasting | kerberos.log | PB-05 |
| T1110 Brute Force | Many failed auth attempts | ssh.log, kerberos.log, ftp.log | skills/01 |
| T1556 Modify Authentication Process | (Endpoint-side; limited network visibility) | - | - |
| T1003 OS Credential Dumping | DCSync over network (T1003.006) | dce_rpc.log + conn.log to DC port 445 | PB-05 |

---

## TA0007 — Discovery

| Technique | Network Indicator | Zeek/Suricata Source | Playbook |
|-----------|-----------------|---------------------|---------|
| T1046 Network Service Discovery | Port scan, service banner grab | conn.log: many unique ports from single src | PB-12 |
| T1018 Remote System Discovery | ICMP sweep, ARP scan, host discovery | conn.log: many unique dst hosts | PB-12 |
| T1135 Network Share Discovery | SMB IPC$/share enumeration | smb_mapping.log | PB-03, PB-12 |
| T1087 Account Discovery | LDAP queries, AD enumeration | dns.log: SRV records + conn.log port 389/636 | PB-12 |
| T1057 Process Discovery | WMI query to remote host | dce_rpc.log | PB-03 |

---

## TA0008 — Lateral Movement

| Technique | Network Indicator | Zeek/Suricata Source | Playbook |
|-----------|-----------------|---------------------|---------|
| T1021.001 RDP | RDP connections from unexpected src | rdp.log | PB-03 |
| T1021.002 SMB/Windows Admin Shares | ADMIN$/C$ share access, service creation | smb_mapping.log, smb_files.log | PB-03 |
| T1021.004 SSH | Internal SSH lateral movement | ssh.log | PB-03 |
| T1021.006 WinRM | WinRM on 5985/5986 from workstations | conn.log | PB-03 |
| T1047 WMI | WMI over DCE/RPC to remote hosts | dce_rpc.log | PB-03 |
| T1550.002 Pass-the-Hash | NTLM where Kerberos expected | ntlm.log | PB-05 |
| T1550.003 Pass-the-Ticket | Kerberos ticket used from unexpected host | kerberos.log | PB-05 |
| T1569.002 Service Execution | Service binary copy to ADMIN$ + start | smb_files.log + dce_rpc.log | PB-03 |

---

## TA0009 — Collection

| Technique | Network Indicator | Zeek/Suricata Source | Playbook |
|-----------|-----------------|---------------------|---------|
| T1039 Data from Network Shared Drive | Mass SMB READ operations from one host | smb_files.log | PB-04 |
| T1074 Data Staged | Large file writes to staging share | smb_files.log | PB-04 |
| T1114 Email Collection | IMAP/Exchange access from unusual host | conn.log port 143/993/443 | PB-04 |

---

## TA0011 — Command and Control

| Technique | Network Indicator | Zeek/Suricata Source | Playbook |
|-----------|-----------------|---------------------|---------|
| T1071.001 Web Protocols (HTTP/S) | Periodic small HTTPS connections | conn.log + ssl.log (beaconing) | PB-01 |
| T1071.004 DNS | DNS beaconing, C2 via TXT records | dns.log | PB-02 |
| T1095 Non-Application Layer Protocol | Custom TCP/UDP C2 protocol | conn.log + PCAP (protocol RE) | PB-14 |
| T1102 Web Service | C2 via Dropbox, Pastebin, Twitter API | http.log + http host analysis | PB-04 |
| T1104 Multi-Stage Channels | Multiple different C2 protocols | correlation across conn.log types | PB-01, PB-10 |
| T1132 Data Encoding | Base64/XOR in HTTP bodies/URIs | http.log: URI entropy, body analysis | PB-13 |
| T1573.001 Symmetric Cryptography | Encrypted payload (high entropy) in HTTP | http.log + PCAP | PB-06 |
| T1573.002 Asymmetric Cryptography | TLS C2 with suspicious certs | ssl.log + x509.log | PB-06, PB-10 |
| T1568.002 DGA | High-entropy domain queries | dns.log | PB-02 |
| T1048.003 Exfiltration over DNS | DNS tunneling | dns.log | PB-02, PB-04 |

---

## TA0010 — Exfiltration

| Technique | Network Indicator | Zeek/Suricata Source | Playbook |
|-----------|-----------------|---------------------|---------|
| T1041 Exfiltration Over C2 Channel | High outbound bytes on C2 connection | conn.log: bytes anomaly on known C2 dst | PB-04 |
| T1048 Exfiltration Over Alternative Protocol | Large DNS TXT, FTP, SMTP with attachments | dns.log, ftp.log, smtp.log | PB-04, PB-02 |
| T1567 Exfiltration Over Web Service | Large upload to cloud storage service | http.log: PUT/POST to cloud domains | PB-04 |
| T1020 Automated Exfiltration | Scheduled large outbound transfers | conn.log: time-of-day analysis | PB-04 |

---

## TA0040 — Impact

| Technique | Network Indicator | Zeek/Suricata Source | Playbook |
|-----------|-----------------|---------------------|---------|
| T1486 Data Encrypted for Impact | Mass SMB write activity | smb_files.log: high WRITE count | PB-11 |
| T1490 Inhibit System Recovery | WMI calls to delete VSS | dce_rpc.log | PB-11 |
| T1489 Service Stop | Service control traffic | smb_mapping.log + dce_rpc.log | PB-11 |
| T1498 Network DoS | Volumetric traffic spike | conn.log: bandwidth anomaly | - |
