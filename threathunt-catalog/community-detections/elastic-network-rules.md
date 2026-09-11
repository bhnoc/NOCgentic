# Elastic Detection Rules — Network Category Catalog

**Source:** https://github.com/elastic/detection-rules/tree/main/rules/network  
**Total rules:** ~60 TOML files  
**Query languages:** ES|QL (ESQL) and KQL  
**Primary data sources:** `logs-network_traffic.*`, `logs-zeek.*`, `logs-panw.panos*`, `logs-fortinet_fortigate.log-*`, `packetbeat-*`

Each rule has: metadata block → rule name/description → EQL/KQL query → ATT&CK tactic+technique tags.

---

## Command and Control (TA0011)

| Rule Name | ATT&CK | Data Source | Detection Logic |
|-----------|--------|-------------|-----------------|
| Cobalt Strike C&C Beacon | T1071.001, T1568.002 | network_traffic, panw, fortinet | Regex on destination domain: `[a-z]{3}\.stage\.[0-9]{8}\..*` in TLS/HTTP |
| Default Cobalt Strike Team Server Certificate | T1071, T1573 | network_traffic.tls, packetbeat | TLS cert hash match: MD5 `950098276A`, SHA1 `6ECE5ECE41`, SHA256 `87F2085C32` |
| Potential Self-Signed TLS Cert (Recent, External) | T1071, T1573.002 | network_traffic.tls | `issuer_dn == subject_dn` AND `not_before >= now()-30d`, src RFC1918, dst external |
| Potential DNS Tunneling via Long Unique Subdomains | T1071.004, T1572, T1048.003 | network_traffic.dns, zeek.dns | `subdomain_length >= 50`; per (client_ip, registered_domain) 5-min window: `count_queries >= 25 AND count_distinct_names >= 15` |
| Potential ICMP Tunneling to Internet | T1095, T1572 | network_traffic.icmp | Oversized ICMP echo payloads from internal to external IPs |
| FIN7 C2 Behavior | T1071 | network_traffic | Patterns associated with known FIN7 C2 infrastructure |
| HalfBaked Beacon | T1071 | network_traffic | Network signatures for HalfBaked implant C2 |
| Newly Observed IPsec NAT Traversal Peer | — | network_traffic | First-seen IPsec UDP/4500 peer from external |
| Telnet Port Connection Accepted | T1021 | network_traffic | Inbound Telnet (TCP/23) accepted connection |
| RDP from the Internet | T1021.001 | network_traffic, panw | Inbound RDP (TCP/3389) from non-RFC1918 source |
| VNC from the Internet | T1021.005 | network_traffic | Inbound VNC (TCP/5900) from external |
| VNC to the Internet | T1021.005 | network_traffic | Outbound VNC from internal host |
| SMTP to Internet Port 26 | T1048 | network_traffic | Outbound TCP/26 (alternative SMTP — common in exfil/spam C2) |
| Download RAR via PowerShell from Internet | T1105 | network_traffic | HTTP download of archive via PowerShell user-agent |

### Key ES|QL Query Pattern — DNS Tunneling

```esql
FROM logs-network_traffic.dns-*, logs-zeek.dns-*
| WHERE network.direction == "egress"
| EVAL subdomain = SPLIT(dns.question.name, ".")
| EVAL subdomain_length = LENGTH(ARRAY_JOIN(SLICE(subdomain, 0, -2), "."))
| WHERE subdomain_length >= 50
| STATS count_queries = COUNT(*), count_distinct_names = COUNT_DISTINCT(dns.question.name)
  BY client.ip, registered_domain, bucket = BUCKET(@timestamp, 5 minute)
| WHERE count_queries >= 25 AND count_distinct_names >= 15
```

### Key ES|QL Query Pattern — Self-Signed TLS

```esql
FROM logs-network_traffic.tls-*
| WHERE tls.server.x509.issuer.distinguished_name == tls.server.x509.subject.distinguished_name
  AND tls.server.x509.not_before >= NOW() - 30 days
  AND CIDR_MATCH(source.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
  AND NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
```

---

## Discovery / Reconnaissance (TA0007 / TA0043)

| Rule Name | ATT&CK | Data Source | Detection Logic |
|-----------|--------|-------------|-----------------|
| Potential Network Scan Detected | T1046, T1595, T1595.001 | network_traffic, panw | From RFC1918 source: `count_distinct_dst_ports >= 50` OR `count_distinct_sensitive_ports >= 5` within 1-min window. Sensitive ports: 21,22,23,53,88,139,389,445,3389,5900,5985,5986,9389 |
| Potential Port Scan Detected | T1046, T1595, T1595.001 | network_traffic, panw | Same threshold logic (ESQL aggregation variant) |
| Potential SYN-Based Port Scan | T1046, T1595, T1595.001 | network_traffic, panw | SYN-only (no ACK) traffic to many ports from single source (KQL) |
| ICMP Timestamp / Info Request from Internet | T1595 | network_traffic | ICMP type 13/15/17 from external — IANA-deprecated recon types |
| Potential SIP Extension Enumeration | T1595 | network_traffic | High volume of SIP OPTIONS/REGISTER to enumerate extensions |

### Key ES|QL Query — Port Scan

```esql
FROM logs-network_traffic.*
| WHERE CIDR_MATCH(source.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
  AND network.type == "ipv4"
| STATS count_distinct_ports = COUNT_DISTINCT(destination.port)
  BY source.ip, bucket = BUCKET(@timestamp, 1 minute)
| WHERE count_distinct_ports >= 50
```

---

## Initial Access (TA0001)

| Rule Name | ATT&CK | Data Source | Detection Logic |
|-----------|--------|-------------|-----------------|
| DNS Rebinding (Public → Private) | T1189 | network_traffic.dns, zeek.dns | Same registered domain resolves to public IP then private IP within 5-min window |
| Unsecure Elasticsearch Node | T1190 | network_traffic | Inbound HTTP to Elasticsearch API (port 9200) without auth from external |
| RPC from the Internet | T1190 | network_traffic | External source to MS-RPC port (TCP/135) |
| RPC to the Internet | T1571 | network_traffic | Internal host initiating RPC to external |
| SMB from the Internet | T1190 | network_traffic | Inbound SMB (TCP/445, 139) from external |
| SMB to the Internet | T1048 | network_traffic | Outbound SMB to external (data exfiltration) |
| Thrift RPC from External Client | T1190 | network_traffic | External connection to Apache Thrift service |
| Potential Redis Lua RCE CVE-2025-49844 | T1190 | network_traffic | Network indicators of Redis Lua vulnerability exploitation |
| React Server Components RCE Attempt | T1190 | network_traffic | HTTP request patterns for RSC deserialization abuse |
| FortiGate Admin Login Multi Source IP | T1078 | fortinet_fortigate | Same admin user from multiple source IPs in short window |
| Splunk Postgres Backup/Restore RCE Sequence | T1190 | network_traffic | Sequence: Postgres backup then command execution on Splunk |

### DNS Rebinding ES|QL Pattern

```esql
FROM logs-network_traffic.dns-*, logs-zeek.dns-*
| WHERE dns.type == "answer" AND dns.resolved_ip IS NOT NULL
| EVAL is_private = CIDR_MATCH(dns.resolved_ip, "10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8")
| STATS
    has_public = MAX(CASE(NOT is_private, 1, 0)),
    has_private = MAX(CASE(is_private, 1, 0))
  BY dns.question.registered_domain, source.ip,
     bucket = BUCKET(@timestamp, 5 minute)
| WHERE has_public == 1 AND has_private == 1
```

---

## Credential Access (TA0006)

| Rule Name | ATT&CK | Data Source | Detection Logic |
|-----------|--------|-------------|-----------------|
| Deprecated TLS / Weak Cipher (External) | T1557, T1573 | network_traffic.tls | TLS version < 1.2 OR negotiated NULL/EXPORT/RC4/DES cipher with external host |
| DHCP Multiple Servers Same Transaction | T1557 | network_traffic | Multiple DHCP offers for same `xid` (rogue DHCP / AiTM position) |
| ICMP Redirect Message Observed | T1557 | network_traffic | ICMP type 5 (redirect) from unexpected source — routing hijack indicator |
| Potential SIP Register Brute Force | T1110 | network_traffic | High volume of SIP REGISTER failures from single source |
| SonicWall Login Failures then Success | T1110 | sonicwall | Sequence: N failed logins then 1 success (credential stuffing) |
| Cloud IMDS Credential HTTP Request | T1552.005 | network_traffic | HTTP GET to `169.254.169.254` IMDS endpoints for credential metadata |

---

## Persistence (TA0003)

| Rule Name | ATT&CK | Data Source | Detection Logic |
|-----------|--------|-------------|-----------------|
| Redis Config Set — SSH Key Injection | T1098 | network_traffic | Redis `CONFIG SET dir/dbfilename` to `.ssh/authorized_keys` path |
| Redis Config Set — Cron Persistence | T1053.003 | network_traffic | Redis `CONFIG SET` to cron directory path |
| MySQL UDF Injection | T1505.001 | network_traffic | MySQL `CREATE FUNCTION` with UDF shared library path (over wire protocol) |
| FortiGate Super Admin Account Creation | T1136 | fortinet_fortigate | New super-admin account created in FortiGate logs |

---

## Lateral Movement (TA0008)

| Rule Name | ATT&CK | Data Source | Detection Logic |
|-----------|--------|-------------|-----------------|
| DNS Server Overflow | T1210 | network_traffic | Oversized DNS responses indicating DNS server exploitation |

---

## Impact (TA0040)

| Rule Name | ATT&CK | Data Source | Detection Logic |
|-----------|--------|-------------|-----------------|
| DHCP Starvation — High Client MAC Cardinality | T1498 | network_traffic | Burst of DHCP DISCOVER from many unique MACs from single IP |
| AMQP Multi-Queue Purge Burst | T1485 | network_traffic | Many AMQP queue purge commands in short window |
| Destructive MongoDB Command | T1485 | network_traffic | `dropDatabase` / `drop` collection commands over wire protocol |
| Potential NFS Destructive Operation Burst | T1485 | network_traffic | High-rate NFS REMOVE or RMDIR operations |
| First Time Seen Memcached Writer | T1485 | network_traffic | New source IP writing to Memcached (data poisoning/destruction) |
| TLS ALPN ACME Stalled Handshake | T1498 | network_traffic | ACME protocol abuse / DoS via stalled TLS-ALPN handshakes |

---

## Collection / Defense Evasion / Execution

| Rule Name | Tactic | ATT&CK | Data Source | Detection Logic |
|-----------|--------|--------|-------------|-----------------|
| FortiGate Config Download | Collection | T1005 | fortinet_fortigate | HTTP GET of FortiGate full config backup |
| NFS AUTH_SYS Root UID Access | Collection | T1005 | network_traffic | NFS request with AUTH_SYS uid=0 (root impersonation) |
| FortiGate Overly Permissive Firewall Policy | Defense Evasion | T1562.004 | fortinet_fortigate | Firewall policy with `any/any` or overly broad access |
| Cassandra JavaScript UDF Creation | Execution | T1059 | network_traffic | Cassandra `CREATE FUNCTION` with `LANGUAGE javascript` |
| PostgreSQL COPY PROGRAM Command | Execution | T1059 | network_traffic | `COPY ... FROM PROGRAM` in Postgres wire protocol (RCE path) |

---

## Integration with Zeek/Suricata

Elastic's network rules consume Zeek via `logs-zeek.*` index pattern (ECS-aligned):

| Zeek Log | ECS Index | Elastic Field Mapping |
|----------|-----------|----------------------|
| dns.log | logs-zeek.dns-* | `dns.question.name`, `dns.resolved_ip`, `zeek.dns.*` |
| ssl.log | logs-zeek.ssl-* | `tls.server.x509.*`, `tls.client.ja3.*` |
| conn.log | logs-zeek.connection-* | `source.ip`, `destination.ip`, `network.bytes` |
| http.log | logs-zeek.http-* | `http.request.method`, `user_agent.original`, `url.*` |
| files.log | logs-zeek.files-* | `file.hash.md5`, `file.name`, `file.mime_type` |

To use these rules with Zeek, ensure your Zeek integration in Elastic Agent is configured and producing ECS-aligned output. Rules targeting `logs-zeek.dns-*` (e.g., DNS tunneling) work directly on Zeek dns.log output.

---

## Summiting the Pyramid — Detection Robustness Scoring

Source: https://github.com/center-for-threat-informed-defense/summiting-the-pyramid

Applied to network hunting, detections are ranked by evasion resistance:

| Robustness Level | Example Network Detection | Adversary Evasion Effort |
|-----------------|--------------------------|--------------------------|
| **Low** (IoC-based) | Block Cobalt Strike cert SHA256 hash | Trivial — regenerate cert |
| **Medium** (Behavioral signature) | Detect CS via malleable C2 URI pattern | Moderate — change profile |
| **High** (TTP-intrinsic) | Detect C2 beaconing via statistical jitter analysis | Hard — must fundamentally change behavior |
| **Very High** (Structural) | Detect DNS tunneling via subdomain entropy regardless of domain | Very hard — must use different technique |

**Takeaway for hunters:** Build detections that target the behavior (long subdomains, irregular intervals, cert mismatch) not the specific tool signatures. The Elastic ESQL rules for DNS tunneling and self-signed certs are medium-to-high robustness — they detect the *behavior*, not the *tool*.
