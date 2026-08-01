# Corelight Data Schema — Black Hat

## Overview

Live network telemetry from Corelight sensors deployed at the Black Hat conference network.

- **S3 Bucket:** `blackhat-pope-dev-logs`
- **Region:** `us-west-2`
- **Prefix:** `nocgentic/corelight/{YYYY-MM-DD}/`
- **Format:** Gzipped Zeek TSV (`.log.gz`) with `#fields` header rows
- **Timestamps:** Unix epoch floats (e.g., `1776752541.431893`)
- **Volume:** ~25,000+ files per day across 60+ log types

### Date Folders
```
nocgentic/corelight/2026-04-21/   (~25,094 files)
nocgentic/corelight/2026-04-22/   (~26,036 files)
```

### File Naming Convention
```
{log_type}_{YYYYMMDD}_{HH:MM:SS}-{HH:MM:SS}+{TZ}-{sensor_id}.log.gz
```
Example: `conn_20260421_14:22:26-14:25:00+0800-1.log.gz`

---

## Common Fields (Present in Most Log Types)

Most connection-based logs share these Zeek identity fields:

| Field | Type | Description |
|-------|------|-------------|
| `ts` | float | Unix epoch timestamp |
| `uid` | string | Unique connection ID (correlates across log types) |
| `id.orig_h` | addr | Source IP |
| `id.orig_p` | port | Source port |
| `id.resp_h` | addr | Destination IP |
| `id.resp_p` | port | Destination port |
| `id.vlan` | int | VLAN tag |
| `id.local_orig` | bool | Source is local network |
| `id.local_resp` | bool | Destination is local network |
| `id.orig_mac` | string | Source MAC address |
| `id.orig_mac_vendor` | string | Source MAC vendor |
| `id.resp_mac` | string | Destination MAC address |
| `id.resp_mac_vendor` | string | Destination MAC vendor |
| `id.orig_network_name` | string | **Source network/training track name** (e.g., "Hands-On Hacking Fundamentals") |
| `id.orig_network_ssid` | string | Source WiFi SSID (e.g., "Peony4404") |
| `id.orig_room_name` | string | Physical room (e.g., "Peony Main Ballroom: 4404") |
| `id.resp_network_name` | string | Destination network name |

> **Note:** The `id.orig_network_name` field maps IPs to Black Hat training tracks, conference areas, and infrastructure segments. This is extremely valuable for understanding _who_ is generating traffic.

---

## High-Value Log Types

### 1. `conn` — Connection Logs (~812 files/day)

Full TCP/UDP/ICMP connection summaries. The foundation for all network analysis.

| Field | Type | Description |
|-------|------|-------------|
| `proto` | enum | `tcp`, `udp`, `icmp` |
| `service` | string | Detected application protocol (e.g., `ssl`, `http`, `dns`) |
| `duration` | float | Connection duration in seconds |
| `orig_bytes` | int | Bytes sent by originator |
| `resp_bytes` | int | Bytes sent by responder |
| `conn_state` | string | Connection state (`SF`=normal, `S0`=SYN no reply, `REJ`=rejected, etc.) |
| `missed_bytes` | int | Bytes missed due to content gaps |
| `history` | string | Connection state history flags |
| `orig_pkts` / `resp_pkts` | int | Packet counts |
| `orig_ip_bytes` / `resp_ip_bytes` | int | IP-level byte counts |
| `community_id` | string | Community ID flow hash (correlates with Suricata) |
| `remote_asn` | int | Remote AS number |
| `remote_organization` | string | Remote org (e.g., "Amazon.com, Inc.") |
| `remote_country` | string | Remote country code (e.g., "SG", "US") |
| `tcp_rtt` | interval | TCP round-trip time |

**Conn state codes:**
- `SF` — Normal established and terminated
- `S0` — SYN sent, no reply (scan indicator)
- `S1` — Connection established, not terminated
- `REJ` — Connection rejected
- `RSTO` — Originator reset
- `OTH` — Other/midstream

### 2. `dns` — DNS Queries (~812 files/day)

All DNS query/response pairs.

| Field | Type | Description |
|-------|------|-------------|
| `proto` | enum | `udp` or `tcp` |
| `trans_id` | int | DNS transaction ID |
| `rtt` | float | Round-trip time |
| `query` | string | **DNS query name** |
| `qclass_name` | string | Query class (usually `C_INTERNET`) |
| `qtype_name` | string | Query type (`A`, `AAAA`, `CNAME`, `TXT`, `MX`, etc.) |
| `rcode_name` | string | Response code (`NOERROR`, `NXDOMAIN`, `SERVFAIL`, etc.) |
| `AA` | bool | Authoritative answer |
| `TC` | bool | Truncated |
| `RD` | bool | Recursion desired |
| `RA` | bool | Recursion available |
| `answers` | vector | DNS answer records |
| `TTLs` | vector | TTL values for answers |
| `rejected` | bool | Query was rejected |
| `icann_domain` | string | Registered domain (e.g., `microsoft.com`) |
| `icann_tld` | string | TLD (e.g., `com`, `net`) |

### 3. `http` — HTTP Requests (~812 files/day)

Full HTTP request/response metadata.

| Field | Type | Description |
|-------|------|-------------|
| `trans_depth` | int | Pipeline depth |
| `method` | string | `GET`, `POST`, `HEAD`, `CONNECT`, etc. |
| `host` | string | HTTP Host header |
| `uri` | string | Request URI |
| `referrer` | string | Referer header |
| `version` | string | HTTP version |
| `user_agent` | string | User-Agent string |
| `request_body_len` | int | Request body size |
| `response_body_len` | int | Response body size |
| `status_code` | int | HTTP status code |
| `status_msg` | string | HTTP status message |
| `resp_mime_types` | vector | Response MIME types |
| `client_headers` | vector | Full client request headers |
| `server_headers` | vector | Full server response headers |

### 4. `ssl` — TLS/SSL Connections (~812 files/day)

TLS handshake metadata with JA3/JA3S fingerprints.

| Field | Type | Description |
|-------|------|-------------|
| `version` | string | TLS version (`TLSv13`, `TLSv12`, etc.) |
| `cipher` | string | Negotiated cipher suite |
| `curve` | string | EC curve (e.g., `x25519`) |
| `server_name` | string | **SNI (Server Name Indication)** |
| `resumed` | bool | Session was resumed |
| `established` | bool | TLS handshake completed |
| `subject` | string | Certificate subject |
| `issuer` | string | Certificate issuer |
| `validation_status` | string | Certificate validation result |
| `ja3` | string | **JA3 client fingerprint hash** |
| `ja3s` | string | **JA3S server fingerprint hash** |
| `ssl_history` | string | TLS handshake state history |
| `ssl_tt_estab` | float | Time to TLS establishment |

### 5. `suricata_corelight` — IDS Alerts (~812 files/day)

Suricata intrusion detection alerts integrated with Corelight.

| Field | Type | Description |
|-------|------|-------------|
| `suri_id` | string | Suricata flow ID |
| `service` | string | Detected service |
| `flow_id` | int | Suricata internal flow ID |
| `alert.action` | string | Alert action (`allowed`, `blocked`) |
| `alert.gid` | int | Generator ID |
| `alert.signature_id` | int | **Suricata rule SID** |
| `alert.rev` | int | Rule revision |
| `alert.signature` | string | **Alert description** (e.g., "ET SCAN Suspicious inbound to mySQL port 3306") |
| `alert.category` | string | **Alert category** (e.g., "Potentially Bad Traffic", "Misc activity") |
| `alert.severity` | int | Severity level (1=high, 2=medium, 3=low) |
| `alert.metadata` | vector | Rule metadata tags |
| `alert.rule` | string | Full Suricata rule text |
| `community_id` | string | Community ID (correlates with conn logs) |
| `payload_printable` | string | Decoded payload content |

### 6. `notice` — Zeek Notices (~262 files/day)

Security-relevant notices generated by Zeek's detection framework.

| Field | Type | Description |
|-------|------|-------------|
| `note` | enum | Notice type (e.g., `SSL::Invalid_Server_Cert`, `Weird::Activity`) |
| `msg` | string | **Human-readable notice message** |
| `sub` | string | Additional detail (e.g., certificate CN) |
| `src` | addr | Source address |
| `dst` | addr | Destination address |
| `p` | port | Associated port |
| `actions` | set | Actions taken (e.g., `Notice::ACTION_LOG`) |
| `severity.level` | int | Severity (1-5) |
| `severity.name` | string | Severity name (`error`, `warning`, `info`) |
| `remote_location.country_code` | string | Geolocation country |
| `remote_location.city` | string | Geolocation city |

### 7. `ssh` — SSH Connections (~173 files/day)

SSH session metadata with HASSH fingerprinting.

| Field | Type | Description |
|-------|------|-------------|
| `version` | int | SSH version |
| `auth_success` | bool | **Authentication succeeded** |
| `auth_attempts` | int | Number of auth attempts |
| `direction` | enum | `INBOUND` or `OUTBOUND` |
| `client` | string | SSH client string |
| `server` | string | SSH server string |
| `cipher_alg` | string | Encryption algorithm |
| `kex_alg` | string | Key exchange algorithm |
| `host_key_alg` | string | Host key algorithm |
| `host_key` | string | Server host key fingerprint |
| `hassh` | string | **HASSH client fingerprint** |
| `hasshServer` | string | **HASSH server fingerprint** |
| `remote_location.*` | various | Geolocation of remote end |

---

## Additional Log Types

### Network Protocols

| Log Type | Files/Day | Description | Key Fields |
|----------|-----------|-------------|------------|
| `dhcp` | ~709 | DHCP lease events | `client_addr`, `server_addr`, `mac`, `host_name`, `domain`, `assigned_addr`, `lease_time` |
| `kerberos` | ~180 | Kerberos authentication | `request_type`, `client`, `service`, `success`, `error_msg`, `cipher` |
| `ntp` | ~812 | NTP time sync | Standard conn fields + NTP specifics |
| `mysql` | ~812 | MySQL protocol events | Standard conn fields |
| `redis` | ~9 | Redis commands | `cmd.name`, `cmd.key`, `cmd.value`, `success`, `reply.value` |
| `snmp` | ~15 | SNMP queries | `version`, `community`, `get_requests`, `set_requests`, `display_string` |
| `ldap_search` | ~81 | LDAP search queries | Standard conn fields + LDAP specifics |
| `ssdp` | ~812 | UPnP/SSDP discovery | Standard conn fields |

### Security & Analysis

| Log Type | Files/Day | Description | Key Fields |
|----------|-----------|-------------|------------|
| `weird` | ~812 | Protocol anomalies | `name` (anomaly type), `addl` (details), `notice` (bool) |
| `files` | ~812 | File transfers observed | `source`, `mime_type`, `filename`, `seen_bytes`, `md5`, `sha1`, `sha256` |
| `x509` | ~315 | X.509 certificates | `certificate.subject`, `certificate.issuer`, `certificate.not_valid_before/after`, `san.dns`, `basic_constraints.ca` |
| `software` | ~356 | Software version detection | `host`, `software_type`, `name`, `version.*`, `unparsed_version` |
| `pe` | ~38 | PE (Windows executable) metadata | File analysis fields |
| `corelight_ml_results` | ~9 | ML-based domain classification | `domain`, `path`, `predicted_tag_name`, `predicted_probability`, `nearest_ref_domain` |

### Encrypted & Tunneled Traffic

| Log Type | Files/Day | Description | Key Fields |
|----------|-----------|-------------|------------|
| `tunnel` | ~445 | Tunnel encapsulation events | `tunnel_type`, `action` |
| `vpn` | ~343 | VPN connections | `vpn_type`, `service`, `server_name`, `client_info`, `ja3`, `ja3s` |
| `encrypted_dns` | ~753 | DNS-over-HTTPS/TLS detection | `resp_h`, `cert.cn`, `cert.sans`, `sni`, `match` |
| `quic` | ~812 | QUIC protocol connections | Standard conn fields |
| `wireguard` | ~161 | WireGuard VPN sessions | Standard conn fields |
| `ipsec` | ~219 | IPsec VPN sessions | Standard conn fields |

### IoT & Industrial

| Log Type | Files/Day | Description | Key Fields |
|----------|-----------|-------------|------------|
| `mqtt_connect` | ~26 | MQTT broker connections | `proto_name`, `proto_version`, `client_id`, `connect_status`, `will_topic` |
| `mqtt_publish` | ~7 | MQTT publish events | Topic and payload metadata |
| `mqtt_subscribe` | ~24 | MQTT subscriptions | Subscription topics |
| `profinet` | ~21 | PROFINET industrial protocol | `operation_type`, `block_version`, `slot_number` |
| `profinet_dce_rpc` | ~21 | PROFINET DCE/RPC | Industrial control specifics |

### Infrastructure & Metadata

| Log Type | Files/Day | Description | Key Fields |
|----------|-----------|-------------|------------|
| `known_hosts` | ~266 | Known internal hosts | `host_ip`, `host_vlan`, `n_opened`, `n_closed`, `n_pending` |
| `known_services` | ~266 | Known services | Service enumeration |
| `known_devices` | ~233 | Known network devices | Device classification |
| `known_domains` | ~47 | Known domains | Domain tracking |
| `known_users` | ~92 | Known user accounts | User enumeration |
| `known_names` | ~221 | Known hostnames | Name resolution |
| `known_certs` | ~28 | Known certificates | Certificate tracking |
| `asset_classification` | ~644 | **Device fingerprinting** | `ip`, `confidence`, `device_type`, `type_name`, `brand`, `model`, `os_name`, `os_ver` |
| `conn_long` | ~630 | Long-lived connections | Same as `conn` + VPC capture metadata |
| `etc_viz` | ~812 | Encrypted traffic analytics | Visibility metadata |

### Sensor Health

| Log Type | Files/Day | Description |
|----------|-----------|-------------|
| `reporter` | ~812 | Zeek internal messages |
| `perf` | ~805 | Sensor performance metrics |
| `smartpcap` / `smartpcap_stats` | ~812 | Smart PCAP capture stats |
| `corelight_overall_capture_loss` | ~472 | Packet capture loss metrics |
| `corelight_ml_metrics` | ~812 | ML engine performance |
| `suricata_stats` | ~811 | Suricata engine stats |
| `analyzer` | ~326 | Protocol analyzer stats |

---

## Network Segments (from `id.orig_network_name`)

The Corelight sensors tag traffic with the originating network segment. Known segments include:

- **Training Tracks:** "Hands-On Hacking Fundamentals", "Adversary Simulation and Capability Development", "Exploiting 10x Faster: LLM Agents and MCPs for Modern Vulnerability Research", "Android Application Hacking", "Advanced Infrastructure Hacking", "Hacking the Final Frontier: Offensive Security in Space Systems and Satellites", "Practical GenAI for Threat Intel: Real-World Agentic Workflows for Cyber Threat Intelligence"
- **Conference WiFi:** "General WiFi (16283 DHCP hosts)" / SSID: `BlackHatAsia2026`
- **NOC WiFi:** "NOC WiFi" / SSID: `SnarkyMess`
- **Infrastructure:** "Registration Hypervisors", "Registration", "OpenDNS/Umbrella DNS Virtual Appliances", "Tool Mgmt"
- **Room identifiers:** SSID maps to physical rooms (e.g., `Peony4404` = Peony Main Ballroom: 4404)

---

## Correlation Keys

| Key | Across | Usage |
|-----|--------|-------|
| `uid` | All connection-based logs | Correlate conn ↔ dns ↔ http ↔ ssl ↔ files for the same connection |
| `community_id` | conn, suricata_corelight | Correlate Zeek connections with Suricata alerts |
| `id.orig_h` + `id.resp_h` | All | IP-based correlation |
| `id.orig_mac` | All | MAC-based device tracking |
| `fuid` | files, notice | File UID correlation |

---

## Agent ↔ Log Type Mapping

| Agent | Primary Log Types | Use Case |
|-------|-------------------|----------|
| `alert-triage` | `suricata_corelight`, `conn` | IDS alerts + flow correlation |
| `athena-hunter` | `conn`, `dns`, `ssl`, `suricata_corelight`, etc. | NL→SQL hunt, IOC enrichment + threat context |
| `search_events` | Any (`conn`, `dns`, `http`, `ssl`, etc.) | Freeform keyword search |

---

*Last updated: 2026-04-21*
*Source: Live Corelight sensors at the Black Hat conference network*
