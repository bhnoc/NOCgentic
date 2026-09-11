# SigmaHQ Network Detection Rules — Threat Hunting Catalog

**Source:** https://github.com/SigmaHQ/sigma/tree/master/rules/network
**Compiled:** 2026-09-10
**Total rules:** 53 across 7 top-level categories

---

## Category Summary

| Category | Sub-categories | Rule Count | Log Source Type |
|----------|---------------|-----------|-----------------|
| `zeek/` | dce_rpc, dns, http, x509, rdp, smb_files, kerberos | 21 | Zeek (Bro) NSM logs |
| `cisco/` | aaa, bgp, ldp | 15 | Cisco IOS/NX-OS AAA/syslog |
| `fortinet/` | fortigate | 7 | FortiGate event logs |
| `dns/` | (generic) | 7 | Any DNS log (category-based) |
| `firewall/` | (generic) | 1 | Any firewall log (category-based) |
| `huawei/` | bgp | 1 | Huawei BGP syslog |
| `juniper/` | bgp | 1 | Juniper BGP syslog |

---

## 1. zeek/ — 21 Rules

Zeek rules use `logsource.product: zeek` with a `service:` field that maps to a specific Zeek log file.

### 1.1 dce_rpc (4 rules) — `zeek_dce_rpc_*.yml`

**Zeek fields used:** `endpoint`, `operation`

| Rule File | Title | ATT&CK Tags | Level |
|-----------|-------|------------|-------|
| `zeek_dce_rpc_mitre_bzar_execution.yml` | MITRE BZAR Indicators for Execution | T1047, T1053.002, T1569.002 | medium |
| `zeek_dce_rpc_mitre_bzar_persistence.yml` | MITRE BZAR Indicators for Persistence | T1547.004 | medium |
| `zeek_dce_rpc_potential_petit_potam_efs_rpc_call.yml` | Potential PetitPotam Attack Via EFS RPC Calls | T1557.001, T1187 | medium |
| `zeek_dce_rpc_smb_spoolss_named_pipe.yml` | SMB Spoolss Name Piped Usage | T1021.002 | medium |

**Example — BZAR Execution:**
```yaml
logsource:
  product: zeek
  service: dce_rpc
detection:
  op7:
    endpoint: 'svcctl'
    operation: 'CreateServiceA'
  op5:
    endpoint: 'IWbemServices'
    operation: 'ExecMethod'
  # ... 10 operations total covering atsvc, svcctl, IWbemServices, ITaskSchedulerService
  condition: 1 of op*
```

**Example — PetitPotam:**
```yaml
logsource:
  product: zeek
  service: dce_rpc
detection:
  selection:
    operation|startswith: 'efs'
  condition: selection
```

### 1.2 dns (5 rules) — `zeek_dns_*.yml`

**Zeek fields used:** `query`, `qtype_name`, `Z` (reserved Z-bit), `id.orig_h`, `id.resp_p`, `answers`, `rejected`

| Rule File | Title | ATT&CK Tags | Level |
|-----------|-------|------------|-------|
| `zeek_dns_kerberos_coercion_via_dns_object_spn_spoofing.yml` | Kerberos Coercion via DNS Object SPN Spoofing | T1557.001, T1187 | high |
| `zeek_dns_mining_pools.yml` | DNS Events Related To Mining Pools | T1569.002, T1496 | low |
| `zeek_dns_nkn.yml` | (NKN network C2 detection) | — | — |
| `zeek_dns_susp_zbit_flag.yml` | Suspicious DNS Z Flag Bit Set | T1095, T1571 | medium |
| `zeek_dns_torproxy.yml` | DNS TOR Proxies | T1048 | medium |

**Example — Z-bit flag (DNS tunneling/SUNBURST indicator):**
```yaml
logsource:
  product: zeek
  service: dns
detection:
  z_flag_unset:
    Z: 0
  exclude_tlds:
    query|endswith: ['.arpa', '.local', '.azure-dns.com', ...]
  exclude_query_types:
    qtype_name: ['ns', 'mx']
  condition: not z_flag_unset and most_probable_valid_domain and not (exclude_tlds or ...)
```

**Example — Kerberos DNS Coercion (CVE-2025-33073):**
```yaml
logsource:
  product: zeek
  service: dns
detection:
  selection:
    query|contains|all:
      - 'UWhRCA'   # base64 signature of marshaled CREDENTIAL_TARGET_INFORMATION
      - 'BAAAA'
  condition: selection
```

### 1.3 http (3 rules) — `zeek_http_*.yml`

**Zeek fields used:** `c-useragent`, `c-uri`, `resp_mime_types`, `host`, `uri`, `user_agent`, `method`, `id.resp_h`

| Rule File | Title | ATT&CK Tags | Level |
|-----------|-------|------------|-------|
| `zeek_http_executable_download_from_webdav.yml` | Executable from Webdav | T1105 | medium |
| `zeek_http_susp_file_ext_from_susp_tld.yml` | HTTP Request to Low Reputation TLD or Suspicious File Extension | (initial-access, c2) | medium |
| `zeek_http_webdav_put_request.yml` | WebDav Put Request | T1048.003 | low |

**Example — Executable from WebDAV:**
```yaml
logsource:
  product: zeek
  service: http
detection:
  selection_webdav:
    - c-useragent|contains: 'WebDAV'
    - c-uri|contains: 'webdav'
  selection_executable:
    - resp_mime_types|contains: 'dosexec'
    - c-uri|endswith: '.exe'
  condition: selection_webdav and selection_executable
```

**Example — Suspicious TLD + malicious extension:**
```yaml
detection:
  selection_suspicious_tld:
    host|endswith: ['.xyz', '.top', '.ru', '.tk', '.pw', '.ga', '.ml', '.cf', ...]
  selection_malicious_ext:
    uri|endswith: ['.exe', '.dll', '.ps1', '.hta', '.bat', '.js', '.vbs', ...]
  selection_malicious_mime:
    resp_mime_types: ['application/x-dosexec', 'application/x-elf', ...]
  condition: selection_suspicious_tld and 1 of selection_malicious_*
```

### 1.4 x509 (1 rule) — `zeek_default_cobalt_strike_certificate.yml`

**Zeek fields used:** `certificate.serial`

| Rule File | Title | ATT&CK Tags | Level |
|-----------|-------|------------|-------|
| `zeek_default_cobalt_strike_certificate.yml` | Default Cobalt Strike Certificate | S0154 (Cobalt Strike) | high |

```yaml
logsource:
  product: zeek
  service: x509
detection:
  selection:
    certificate.serial: 8BB00EE   # default CS self-signed cert serial
  condition: selection
```

### 1.5 rdp (1 rule) — `zeek_rdp_public_listener.yml`

**Zeek fields used:** `id.orig_h` (CIDR matching for RFC-1918 exclusion)

```yaml
logsource:
  product: zeek
  service: rdp
detection:
  selection:
    id.orig_h|cidr: ['10.0.0.0/8', '192.168.0.0/16', '172.16.0.0/12', ...]
  condition: not selection   # fires on NON-private source IPs connecting to RDP
tags: [attack.lateral-movement, attack.t1021.001]
level: high
```

### 1.6 smb_files (6 rules) — `zeek_smb_*.yml`

**Zeek fields used:** `path`, `name` (on `smb_files` log)

| Rule File | Title | ATT&CK Tags | Level |
|-----------|-------|------------|-------|
| `zeek_smb_converted_win_atsvc_task.yml` | AT Service Scheduled Task via SMB | T1053.002 | medium |
| `zeek_smb_converted_win_impacket_secretdump.yml` | Possible Impacket SecretDump Remote Activity | T1003.002, T1003.003, T1003.004 | high |
| `zeek_smb_converted_win_lm_namedpipe.yml` | First Time Seen Remote Named Pipe | T1021.002 | high |
| `zeek_smb_converted_win_susp_psexec.yml` | Suspicious PsExec Execution | T1021.002 | high |
| `zeek_smb_converted_win_susp_raccess_sensitive_fext.yml` | Suspicious Access to Sensitive File Extensions | (collection) | medium |
| `zeek_smb_converted_win_transferring_files_with_credential_data.yml` | Transferring Files with Credential Data | T1003.001, T1003.002, T1003.003 | medium |

**Example — Impacket SecretDump:**
```yaml
logsource:
  product: zeek
  service: smb_files
detection:
  selection:
    path|contains|all: ['\\', 'ADMIN$']
    name|contains: 'SYSTEM32\'
    name|endswith: '.tmp'
  condition: selection
```

**Example — Credential file transfer (ntds.dit, SAM, LSASS dump):**
```yaml
detection:
  selection:
    name:
      - '\ntds.dit'
      - '\sam'
      - '\lsass'
      - '\mimidrv'
      - '\hiberfil'
      - '\security'
      - '\windows\minidump\'
  condition: selection
```

**Example — Sensitive file extension over SMB:**
```yaml
detection:
  selection:
    name|endswith: ['.pst', '.ost', '.edb', '.nsf', '.kirbi', '.rdp', '.dmp', '.bak']
  condition: selection
```

### 1.7 kerberos (1 rule) — `zeek_susp_kerberos_rc4.yml`

**Zeek fields used:** `request_type`, `cipher`, `service`

```yaml
logsource:
  product: zeek
  service: kerberos
detection:
  selection:
    request_type: 'TGS'
    cipher: 'rc4-hmac'   # RC4 in TGS request = likely Kerberoasting
  computer_acct:
    service|startswith: '$'
  condition: selection and not computer_acct
tags: [attack.credential-access, attack.t1558.003]
level: medium
```

---

## 2. dns/ — 7 Rules (Generic DNS Category)

These rules use `logsource.category: dns` (vendor-agnostic; works with Zeek dns.log, Windows DNS debug logs, Sysmon, etc.).

**Fields used:** `query`, `record_type`, `answer`

| Rule File | Title | ATT&CK Tags | Level |
|-----------|-------|------------|-------|
| `net_dns_external_service_interaction_domains.yml` | DNS Query to External Service Interaction Domains (OAST) | T1190, T1595.002 | high |
| `net_dns_mal_cobaltstrike.yml` | Cobalt Strike DNS Beaconing | T1071.004 | critical |
| `net_dns_pua_cryptocoin_mining_xmr.yml` | Cryptocurrency Mining DNS Queries (XMR) | T1496 | low |
| `net_dns_susp_b64_queries.yml` | Suspicious DNS Query with B64 Encoded String | T1048.003, T1071.004 | medium |
| `net_dns_susp_telegram_api.yml` | Telegram Bot API Request | T1102.002 | medium |
| `net_dns_susp_txt_exec_strings.yml` | DNS TXT Answer with Possible Execution Strings | T1071.004 | high |
| `net_dns_wannacry_killswitch_domain.yml` | Wannacry Killswitch Domain | T1071.001 | high |

**Example — Cobalt Strike DNS beaconing:**
```yaml
logsource:
  category: dns
detection:
  selection1:
    query|startswith: ['aaa.stage.', 'post.1']
  selection2:
    query|contains: '.stage.123456.'
  condition: 1 of selection*
```

**Example — OAST callback domains (Burp Collaborator, interactsh, canary tokens):**
```yaml
detection:
  selection:
    query|endswith:
      - '.burpcollaborator.net'
      - '.oastify.com'
      - '.interact.sh'
      - '.oast.fun'
      - '.canarytokens.com'
      - '.dnslog.cn'
      - '.dnslog.ink'
      # 25+ domains total
  condition: selection and not filter_main_polling
```

**Example — DNS TXT C2 execution (PowerShell IEX via TXT record):**
```yaml
logsource:
  category: dns
detection:
  selection:
    record_type: 'TXT'
    answer|contains: ['IEX', 'Invoke-Expression', 'cmd.exe']
  condition: selection
```

---

## 3. firewall/ — 1 Rule

| Rule File | Title | ATT&CK Tags | Level |
|-----------|-------|------------|-------|
| `net_firewall_cleartext_protocols.yml` | Cleartext Protocol Usage | (credential-access) | low |

**Fields used:** `dst_port`, `action`, `blocked`

```yaml
logsource:
  category: firewall
detection:
  selection:
    dst_port: [21, 23, 80, 1433, 3306, 5900-5904, 8080, 27017, ...]  # FTP, Telnet, HTTP, VNC, etc.
  selection_allow1:
    action: [forward, accept, 2]
  selection_allow2:
    blocked: "false"
  condition: selection and 1 of selection_allow*
```

---

## 4. cisco/ — 15 Rules

### 4.1 cisco/aaa/ — 13 Rules

All rules use `logsource.product: cisco / service: aaa` (CLI command accounting logs).
**Detection method:** keyword matching on command strings.

| Rule File | Title | ATT&CK Tags | Level |
|-----------|-------|------------|-------|
| `cisco_cli_clear_logs.yml` | Cisco Clear Logs | T1070.003 | high |
| `cisco_cli_collect_data.yml` | Cisco Collect Data | (collection) | — |
| `cisco_cli_crypto_actions.yml` | Cisco Crypto Commands | T1553.004, T1552.004 | high |
| `cisco_cli_disable_logging.yml` | Cisco Disabling Logging | T1685 | high |
| `cisco_cli_discovery.yml` | Cisco Discovery | T1016, T1018, T1033, T1049, T1057, T1082, T1083, T1124, T1201 | low |
| `cisco_cli_dos.yml` | Cisco DoS Commands | (impact) | — |
| `cisco_cli_dot1x_disabled.yml` | Cisco 802.1x Disabled | (defense-impairment) | — |
| `cisco_cli_file_deletion.yml` | Cisco File Deletion | (defense-evasion) | — |
| `cisco_cli_input_capture.yml` | Cisco Show Commands Input | T1552.003 | medium |
| `cisco_cli_local_accounts.yml` | Cisco Local Accounts | (persistence) | — |
| `cisco_cli_modify_config.yml` | Cisco Modify Config | (persistence) | — |
| `cisco_cli_moving_data.yml` | Cisco Stage Data | T1074, T1105, T1560.001 | low |
| `cisco_cli_net_sniff.yml` | Cisco Sniffing | T1040 | medium |

**Example — Clear logs:**
```yaml
detection:
  keywords: ['clear logging', 'clear archive']
  condition: keywords
```

**Example — Certificate/key operations:**
```yaml
detection:
  keywords: ['crypto pki export', 'crypto pki import', 'crypto pki trustpoint']
  condition: keywords
```

**Example — Network sniffing setup:**
```yaml
detection:
  keywords: ['monitor capture point', 'set span', 'set rspan']
  condition: keywords
```

### 4.2 cisco/bgp/ — 1 Rule

| Rule File | Title | ATT&CK Tags | Level |
|-----------|-------|------------|-------|
| `cisco_bgp_md5_auth_failed.yml` | Cisco BGP Authentication Failures | T1078, T1110, T1557 | low |

```yaml
logsource:
  product: cisco
  service: bgp
detection:
  keywords_bgp_cisco:
    '|all': [':179', 'IP-TCP-3-BADAUTH']
  condition: keywords_bgp_cisco
```

### 4.3 cisco/ldp/ — 1 Rule

| Rule File | Title | ATT&CK Tags | Level |
|-----------|-------|------------|-------|
| `cisco_ldp_md5_auth_failed.yml` | Cisco LDP Authentication Failures | T1078, T1110, T1557 | low |

Detection on `SOCKET_TCP_PACKET_MD5_AUTHEN_FAIL` or `TCPMD5AuthenFail` with `LDP` keyword in same log line.

---

## 5. fortinet/ — 7 Rules (all under fortigate/)

All rules use `logsource.product: fortigate / service: event`.
**Fields used:** `action`, `cfgpath`

| Rule File | Title | ATT&CK Tags | Level |
|-----------|-------|------------|-------|
| `fortinet_fortigate_new_admin_account_created.yml` | New Administrator Account Created | T1136.001 | medium |
| `fortinet_fortigate_new_firewall_address_object.yml` | New Firewall Address Object | (persistence) | medium |
| `fortinet_fortigate_new_firewall_policy_added.yml` | New Firewall Policy Added | T1686.002 | medium |
| `fortinet_fortigate_new_local_user_created.yml` | New Local User Created | T1136.001 | medium |
| `fortinet_fortigate_new_vpn_ssl_web_portal.yml` | New VPN SSL Web Portal Added | T1133 | medium |
| `fortinet_fortigate_user_group_modified.yml` | User Group Modified | (persistence) | medium |
| `fortinet_fortigate_vpn_ssl_settings_modified.yml` | VPN SSL Settings Modified | T1133 | medium |

**Example — Admin account creation:**
```yaml
detection:
  selection:
    action: 'Add'
    cfgpath: 'system.admin'
  condition: selection
```

**Example — VPN SSL portal addition (observed in FG-IR-24-535 exploitation):**
```yaml
detection:
  selection:
    action: 'Add'
    cfgpath: 'vpn.ssl.web.portal'
  condition: selection
```

---

## 6. huawei/ — 1 Rule

| Rule File | Title | ATT&CK Tags | Level |
|-----------|-------|------------|-------|
| `huawei/bgp/huawei_bgp_auth_failed.yml` | Huawei BGP Authentication Failures | T1078, T1110, T1557 | low |

```yaml
logsource:
  product: huawei
  service: bgp
detection:
  keywords_bgp_huawei:
    '|all': [':179', 'BGP_AUTH_FAILED']
  condition: keywords_bgp_huawei
```

---

## 7. juniper/ — 1 Rule

| Rule File | Title | ATT&CK Tags | Level |
|-----------|-------|------------|-------|
| `juniper/bgp/juniper_bgp_missing_md5.yml` | Juniper BGP Missing MD5 | T1078, T1110, T1557 | low |

```yaml
logsource:
  product: juniper
  service: bgp
detection:
  keywords_bgp_juniper:
    '|all': [':179', 'missing MD5 digest']
  condition: keywords_bgp_juniper
```

---

## Zeek Log Source Summary

| Zeek Log (service:) | Rules Using It | Key Fields |
|---------------------|---------------|-----------|
| `dce_rpc` | 4 | `endpoint`, `operation` |
| `dns` | 5 | `query`, `Z`, `qtype_name`, `id.orig_h`, `id.resp_p`, `answers`, `rejected` |
| `http` | 3 | `host`, `uri`, `c-uri`, `c-useragent`, `user_agent`, `method`, `resp_mime_types`, `id.resp_h` |
| `x509` | 1 | `certificate.serial` |
| `rdp` | 1 | `id.orig_h` |
| `smb_files` | 6 | `path`, `name` |
| `kerberos` | 1 | `request_type`, `cipher`, `service` |

---

## All Unique ATT&CK Technique IDs (44 T-codes + 1 software)

### Credential Access
| Technique | Name | Rules |
|-----------|------|-------|
| T1003.001 | OS Credential Dumping: LSASS Memory | zeek smb |
| T1003.002 | OS Credential Dumping: SAM | zeek smb |
| T1003.003 | OS Credential Dumping: NTDS | zeek smb |
| T1003.004 | OS Credential Dumping: LSA Secrets | zeek smb |
| T1040 | Network Sniffing | cisco aaa |
| T1110 | Brute Force | cisco/huawei/juniper bgp |
| T1552.003 | Unsecured Credentials: Bash History | cisco aaa |
| T1552.004 | Unsecured Credentials: Private Keys | cisco aaa |
| T1557 | Adversary-in-the-Middle | bgp rules |
| T1557.001 | AiTM: LLMNR/NBT-NS Poisoning | zeek dce_rpc |
| T1558.003 | Kerberoasting | zeek kerberos |

### Execution
| Technique | Name | Rules |
|-----------|------|-------|
| T1047 | Windows Management Instrumentation | zeek dce_rpc |
| T1053.002 | Scheduled Task/Job: AT | zeek dce_rpc, smb |
| T1569.002 | System Services: Service Execution | zeek dce_rpc, dns |

### Persistence
| Technique | Name | Rules |
|-----------|------|-------|
| T1078 | Valid Accounts | bgp rules, cisco |
| T1133 | External Remote Services | fortinet vpn |
| T1136.001 | Create Account: Local Account | fortinet |
| T1547.004 | Boot/Logon Autostart: Print Processors | zeek dce_rpc |

### Privilege Escalation
(shared with Persistence and Credential Access above)

### Defense Evasion
| Technique | Name | Rules |
|-----------|------|-------|
| T1070.003 | Indicator Removal: Clear Command History | cisco aaa |
| T1553.004 | Subvert Trust Controls: Install Root Cert | cisco aaa |
| T1685 | (Disable logging — Cisco-specific) | cisco aaa |
| T1686.002 | (Firewall policy manipulation) | fortinet |

### Discovery
| Technique | Name | Rules |
|-----------|------|-------|
| T1016 | System Network Configuration Discovery | cisco aaa |
| T1018 | Remote System Discovery | cisco aaa |
| T1033 | System Owner/User Discovery | cisco aaa |
| T1049 | System Network Connections Discovery | cisco aaa |
| T1057 | Process Discovery | cisco aaa |
| T1082 | System Information Discovery | cisco aaa |
| T1083 | File and Directory Discovery | cisco aaa |
| T1124 | System Time Discovery | cisco aaa |
| T1201 | Password Policy Discovery | cisco aaa |

### Lateral Movement
| Technique | Name | Rules |
|-----------|------|-------|
| T1021.001 | Remote Services: RDP | zeek rdp |
| T1021.002 | Remote Services: SMB/Admin Shares | zeek smb |

### Collection
| Technique | Name | Rules |
|-----------|------|-------|
| T1074 | Data Staged | cisco aaa |
| T1187 | Forced Authentication | zeek dce_rpc, dns |
| T1560.001 | Archive Collected Data: Archive via Utility | cisco aaa |

### Exfiltration
| Technique | Name | Rules |
|-----------|------|-------|
| T1048 | Exfiltration Over Alternative Protocol | zeek dns |
| T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | dns, zeek http |

### Command and Control
| Technique | Name | Rules |
|-----------|------|-------|
| T1071.001 | Application Layer Protocol: Web Protocols | dns (wannacry) |
| T1071.004 | Application Layer Protocol: DNS | dns rules |
| T1095 | Non-Application Layer Protocol | zeek dns z-bit |
| T1102.002 | Web Service: Bidirectional Communication | dns telegram |
| T1105 | Ingress Tool Transfer | zeek http, cisco aaa |
| T1571 | Non-Standard Port | zeek dns z-bit |

### Impact
| Technique | Name | Rules |
|-----------|------|-------|
| T1496 | Resource Hijacking (crypto mining) | dns, zeek dns |

### Reconnaissance
| Technique | Name | Rules |
|-----------|------|-------|
| T1595.002 | Active Scanning: Vulnerability Scanning | dns oast |

### Initial Access
| Technique | Name | Rules |
|-----------|------|-------|
| T1190 | Exploit Public-Facing Application | dns oast |

### Software
| ID | Name | Rules |
|----|------|-------|
| S0154 | Cobalt Strike | zeek x509, dns |

---

## Notes for Implementation

### Zeek-Specific Field Name Mapping (Sigma → Zeek log field)
- `endpoint` / `operation` → `dce_rpc.log` fields (mapped by Zeek BZAR package)
- `certificate.serial` → `x509.log` field `certificate.serial`
- `id.orig_h` / `id.resp_h` / `id.resp_p` → connection tuple fields present in most Zeek logs
- `Z` → `dns.log` field `Z` (DNS header reserved bit)
- `request_type` / `cipher` → `kerberos.log` fields
- `c-useragent` → alias for Zeek `http.log` `user_agent`
- `resp_mime_types` → `http.log` field (array of MIME types in response)

### Generic Category Rules
- `logsource.category: dns` rules work against Zeek `dns.log`, Sysmon Event 22, Windows DNS debug log, or any SIEM-normalized DNS source
- `logsource.category: firewall` rules work against any firewall log with `dst_port`, `action`, `blocked` fields

### No Suricata or Proxy Rules in scope
- As of the September 2026 snapshot there are **no** rules under `rules/network/suricata/` or `rules/network/proxy/` in the main SigmaHQ/sigma repository. Suricata coverage lives in the separate `SigmaHQ/sigma-rules` release pack converted to Suricata syntax.
- Proxy/web gateway rules are located under `rules/proxy/` (a separate top-level directory, not under `rules/network/`).
