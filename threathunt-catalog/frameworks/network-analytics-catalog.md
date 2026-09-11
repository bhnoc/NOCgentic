# Network-Observable Threat Hunting Analytics Catalog

Compiled from MITRE CAR, Palantir ADS Framework, and Red Canary annual report.
Fetched: 2026-09-10.

---

## Part 1 — MITRE CAR Network Analytics

**Source**: https://car.mitre.org/analytics/  
**Total CAR analytics**: 92 (2013–2022)  
**Network-relevant subset below**: 19 analytics

Each entry: CAR ID | Technique(s) | Data model / log source | Pseudocode / query

---

### CAR-2013-01-003 — SMB Events Monitoring

| Field | Value |
|---|---|
| ATT&CK | T1039 Data from Network Shared Drive · T1021/002 SMB/Windows Admin Shares |
| Tactic | Collection · Lateral Movement |
| Coverage | Moderate |
| Log source | Network flow (port 445 / SMB protocol metadata) |
| Type | Situational Awareness |

**Description**: SMB traffic on port 445 is ubiquitous in Windows environments. Adversaries use it for lateral movement and data collection. High volume makes this best used forensically after incident discovery to determine breadth of access.

**Pseudocode**:
```
flow = search Flow:Message
smb_events = filter flow where (dest_port == "445" and protocol == "smb")
smb_events.file_name = smb_events.proto_info.file_name
output smb_events
```

---

### CAR-2013-02-012 — User Logged in to Multiple Hosts

| Field | Value |
|---|---|
| ATT&CK | T1078/002 Domain Accounts · T1078/003 Local Accounts |
| Tactic | Lateral Movement |
| Coverage | Moderate |
| Log source | Authentication events (Windows Event Log 4624) |

**Description**: Normal users access one or two machines regularly. Accounts authenticating to many hosts — especially within short windows — indicate compromised credentials used for lateral movement. Requires whitelisting administrator and service accounts.

**Pseudocode**: Aggregate EventCode 4624 by user, count distinct dest_host where logon_type in (3,10); flag accounts exceeding threshold (tune per environment, e.g. >5 hosts in 1 hour).

---

### CAR-2013-05-003 — SMB Write Request

| Field | Value |
|---|---|
| ATT&CK | T1570 Lateral Tool Transfer · T1021/002 SMB/Windows Admin Shares · T1078/002 Domain Accounts · T1078/003 Local Accounts |
| Tactic | Lateral Movement |
| Coverage | Moderate |
| Log source | Network flow (port 445, SMB write sub-protocol) |

**Description**: SMB write activity requires higher privilege than reads, producing less noise. Detects file staging for lateral movement or exfiltration over Windows shares.

**Pseudocode**:
```
flow = search Flow:Message
smb_write = filter flow where (dest_port == "445" and protocol == "smb.write")
smb_write.file_name = smb_write.proto_info.file_name
output smb_write
```

---

### CAR-2013-05-005 — SMB Copy and Execution

| Field | Value |
|---|---|
| ATT&CK | T1021/002 SMB/Windows Admin Shares · T1570 Lateral Tool Transfer · T1078/002 · T1078/003 |
| Tactic | Lateral Movement |
| Coverage | Moderate |
| Log source | Network flow (SMB) joined with endpoint process events |

**Description**: Combines SMB file write detection (CAR-2013-05-003) with process creation evidence on the target host. Two-stage correlation: file appears on remote host via SMB, then executes. The combination is a strong lateral movement indicator.

**Pseudocode**:
```
process = search Process:Create
smb_write = run Analytic:CAR-2013-05-003

remote_start = join (smb_write, process) where (
  smb_write.hostname == process.hostname and
  smb_write.file_path == process.image_path and
  smb_write.time < process.time
)
output remote_start
```

---

### CAR-2013-07-002 — RDP Connection Detection

| Field | Value |
|---|---|
| ATT&CK | T1021 Remote Services · T1021/001 Remote Desktop Protocol |
| Tactic | Lateral Movement |
| Coverage | Moderate |
| Log source | Network flow (port 3389) |

**Description**: RDP on port 3389/tcp is a primary lateral movement vector. Baselining normal RDP source hosts and flagging new or unexpected source IPs — especially workstation-to-workstation RDP — reveals adversarial activity. Also correlate with CAR-2016-04-005 for authentication events.

**Pseudocode**:
```
flow_start = search Flow:Start
flow_end   = search Flow:End
rdp_start  = filter flow_start where (dest_port == "3389")
rdp_end    = filter flow_end   where (dest_port == "3389")
rdp = group rdp_start, rdp_end by src_ip, src_port, dest_ip, dest_port
output rdp
```

*Sigma rule available*: Neo23x0/sigma — detect RDP from localhost or unusual sources.

---

### CAR-2013-09-003 — SMB Session Setups

| Field | Value |
|---|---|
| ATT&CK | T1187 Forced Authentication |
| Tactic | Credential Access |
| Coverage | Low |
| Log source | Network flow (port 445, SMB setup sub-protocol) |

**Description**: SMB session setup messages carry user credentials and target hostnames. Monitoring which users authenticate to which hosts via SMB supports detecting credential abuse and mapping attacker lateral movement paths.

**Pseudocode**:
```
flow = search Flow:Message
smb_setup = filter flow where (dest_port == 445 and protocol == "smb.setup")
smb_setup.user        = smb_setup.proto_info.user_name
smb_setup.target_host = smb_setup.proto_info.hostname
output smb_setup
```

---

### CAR-2014-03-001 — SMB Write Request — Named Pipes

| Field | Value |
|---|---|
| ATT&CK | T1570 Lateral Tool Transfer |
| Tactic | Lateral Movement |
| Coverage | Low |
| Log source | Network flow (port 445, SMB named-pipe write) |

**Description**: Named pipes over SMB are used by many Windows services (WINREG, ATSVC, spoolss) but also by attacker tools for remote execution. Separates named-pipe writes from file writes to reduce noise. Whitelist known-benign pipes (e.g. spoolss); investigate lsarpc, svcctl, atsvc.

**Pseudocode**:
```
flow = search Flow:Message
smb_write = filter flow where (dest_port == "445" and protocol == "smb.write_pipe")
smb_write.pipe_name = smb_write.proto_info.pipe_name
output smb_write
```

**Notable pipes to investigate**: `\lsarpc`, `\svcctl`, `\atsvc`, `\winreg`, `\samr`  
**Whitelist candidates**: `\spoolss`, `\msftewds`

---

### CAR-2014-05-001 — RPC Activity

| Field | Value |
|---|---|
| ATT&CK | T1021/002 SMB/Admin Shares · T1021/003 DCOM · T1021/006 WinRM · T1543/003 Windows Services · T1569/002 Execute Services · T1053 Scheduled Tasks · T1047 WMI |
| Tactic | Lateral Movement · Execution |
| Coverage | Moderate |
| Log source | Network flow (port 135 + dynamic ephemeral ports 49152–65535) |

**Description**: Windows RPC first contacts the Endpoint Mapper on port 135/tcp, which responds with a dynamic high port. Join these two flows to reconstruct RPC sessions. Workstation-to-workstation RPC is anomalous; focus on source/dest pairs that deviate from server-to-workstation norms.

**Pseudocode**:
```
flows       = search Flow:Start
rpc_mapper  = filter flows where (dest_port == 135)
rpc_endpoint = filter flows where (dest_port >= 49152 and src_port >= 49152)

rpc = join rpc_mapper, rpc_endpoint where (
  (rpc_mapper.time < rpc_endpoint.time < rpc_mapper.time + 2 seconds) and
  (rpc_mapper.src_ip  == rpc_endpoint.src_ip) and
  (rpc_mapper.dest_ip == rpc_endpoint.dest_ip)
)
output rpc
```

---

### CAR-2014-11-004 — Remote PowerShell Sessions

| Field | Value |
|---|---|
| ATT&CK | T1059/001 PowerShell · T1021/006 Windows Remote Management |
| Tactic | Execution · Lateral Movement |
| Coverage | Moderate |
| Log source | Endpoint process events (Sysmon EventID 1) |

**Description**: When `Enter-PSSession` is invoked, WinRM spawns `wsmprovhost.exe` as a child of `svchost.exe` on the remote host. This parent-child relationship is a reliable indicator of inbound remote PowerShell. Pair with CAR-2014-11-006 (WinRM network) for layered detection.

**Pseudocode**:
```
process = search Process:Create
wsmprovhost = filter process where (
  exe == "wsmprovhost.exe" and
  parent_exe == "svchost.exe"
)
output wsmprovhost
```

**EQL**:
```eql
process where subtype.create and
  process_name == "wsmprovhost.exe" and
  parent_process_name == "svchost.exe"
```

**LogPoint**:
```
norm_id=WindowsSysmon event_id=1 image="*\wsmprovhost.exe" parent_image="*\svchost.exe"
```

---

### CAR-2014-11-006 — Windows Remote Management (WinRM)

| Field | Value |
|---|---|
| ATT&CK | T1021 Remote Services · T1021/006 Windows Remote Management |
| Tactic | Lateral Movement |
| Coverage | Moderate |
| Log source | Network flow (ports 5985/5986) |
| Type | Situational Awareness |

**Description**: WinRM traffic goes to port 5985 (HTTP) or 5986 (HTTPS) with URI `/wsman`. Monitoring these ports provides network-level visibility into all remote PowerShell and WinRM-based lateral movement, complementing host-based detection of wsmprovhost.exe.

**Pseudocode**:
```
flow     = search Flow:Start
winrm    = filter flow where (dest_port == 5985)
winrm_s  = filter flow where (dest_port == 5986)
output winrm, winrm_s
```

---

### CAR-2014-11-007 — Remote WMI over RPC

| Field | Value |
|---|---|
| ATT&CK | T1047 Windows Management Instrumentation |
| Tactic | Execution |
| Coverage | Moderate |
| Log source | Network flow with RPC decode (port 135, IRemUnknown2 interface) |

**Description**: WMI uses DCOM over RPC. The initial connection to port 135 targets the `IRemUnknown2` interface identifier. Detecting this specific RPC interface at the network layer pinpoints WMI lateral movement without requiring host-level telemetry. Complements CAR-2014-05-001.

**Pseudocode**:
```
flows    = search Flow:Message
wmi_flow = filter flows where (
  dest_port == 135 and
  proto_info.rpc_interface == "IRemUnknown2"
)
output wmi_flow
```

---

### CAR-2016-04-005 — Remote Desktop Logon

| Field | Value |
|---|---|
| ATT&CK | T1021 Remote Services · T1021/001 Remote Desktop Protocol |
| Tactic | Lateral Movement |
| Coverage | Moderate |
| Log source | Windows Security Event Log (EventID 4624, LogonType 10) |

**Description**: Windows Event 4624 with LogonType 10 (RemoteInteractive) and AuthenticationPackageName "Negotiate" identifies successful RDP logons. Combine with a whitelist of authorized source hosts to surface unauthorized RDP lateral movement.

**Pseudocode / Splunk**:
```
EventCode == 4624 AND
AuthenticationPackageName == "Negotiate" AND
LogonType == 10
```

**LogPoint**:
```
norm_id=WinServer event_id=4624 package="Negotiate" log_level="INFO" logon_type=10
```

---

### CAR-2020-11-002 — Local Network Sniffing

| Field | Value |
|---|---|
| ATT&CK | T1040 Network Sniffing |
| Tactic | Credential Access · Discovery |
| Coverage | Moderate |
| Log source | Endpoint process events (Sysmon EventID 1) |

**Description**: Adversaries deploy packet capture tools to harvest credentials and session data. Detection targets process creation of well-known sniffing binaries. High-confidence in environments where admins do not routinely run these tools; requires whitelisting in SOC/network teams' workstations.

**Tools detected**: `tshark.exe`, `windump.exe`, `tcpdump.exe`, `wprui.exe`, `wpr.exe`; `logman.exe` (excluding legitimate Windows Event Reporting parent)

**Splunk (Sysmon)**:
```splunk
index=sysmon EventCode=1
  (Image="*\tshark.exe" OR Image="*\windump.exe" OR Image="*\tcpdump.exe"
   OR Image="*\wprui.exe" OR Image="*\wpr.exe"
   OR (Image="*\logman.exe" AND NOT ParentImage="*\Windows\System32\*"))
```

---

### CAR-2020-11-007 — Network Share Connection Removal

| Field | Value |
|---|---|
| ATT&CK | T1070 Indicator Removal · T1070/005 Network Share Connection Removal |
| Tactic | Defense Evasion |
| Coverage | Moderate |
| Log source | Endpoint process events (Sysmon EventID 1) |

**Description**: Adversaries remove mapped network shares after use to eliminate evidence. `net use * /delete` and PowerShell equivalents are rare in most environments, making them high-fidelity indicators when detected.

**Pseudocode**: Detect `net.exe` with `delete` in command line, or PowerShell with `Remove-SmbShare` / `Remove-FileShare`.

**Splunk (Sysmon)**:
```splunk
index=sysmon EventCode=1
  ((Image="C:\\Windows\\System32\\net.exe" AND CommandLine="*delete*")
   OR CommandLine="*Remove-SmbShare*"
   OR CommandLine="*Remove-FileShare*")
```

---

### CAR-2021-01-001 — Identifying Port Scanning Activity

| Field | Value |
|---|---|
| ATT&CK | T1046 Network Service Discovery |
| Tactic | Discovery |
| Coverage | Moderate |
| Log source | Firewall / netflow logs |

**Description**: Post-compromise hosts conduct internal reconnaissance via port scans (Nmap, Cobalt Strike built-in). Detection identifies a single internal source IP connecting to more than a threshold number of distinct destination ports on the internal subnet.

**Splunk**:
```splunk
sourcetype="firewall_logs" dest_ip="internal_subnet"
| stats dc(dest_port) as pcount by src_ip
| where pcount > 5
```

*Tune threshold based on environment baseline. In segmented networks, any cross-segment port contact may be sufficient.*

---

### CAR-2021-02-001 — Webshell-Indicative Process Tree

| Field | Value |
|---|---|
| ATT&CK | T1505/003 Web Shell |
| Tactic | Persistence |
| Coverage | Moderate |
| Log source | Endpoint process events (Sysmon EventID 1) |

**Description**: Web shells execute OS commands via web server processes. Detection identifies enumeration tools spawned by web server parent processes — a pattern never seen in normal web application operation.

**Parent processes**: `w3wp.exe`, `httpd.exe`, `tomcat*.exe`, `nginx.exe`  
**Child processes flagged**: `cmd.exe`, `powershell.exe`, `net.exe`, `whoami.exe`, `hostname.exe`, `systeminfo.exe`, `ipconfig.exe`

**Splunk (Sysmon)**:
```splunk
index=sysmon EventCode=1
  (ParentImage="*\w3wp.exe" OR ParentImage="*\httpd.exe"
   OR ParentImage="*\tomcat*.exe" OR ParentImage="*\nginx.exe")
  (Image="*\cmd.exe" OR Image="*\powershell.exe" OR Image="*\net.exe"
   OR Image="*\whoami.exe" OR Image="*\hostname.exe"
   OR Image="*\systeminfo.exe" OR Image="*\ipconfig.exe")
```

---

### CAR-2021-05-005 — BITSAdmin Download File

| Field | Value |
|---|---|
| ATT&CK | T1197 BITS Jobs · T1105 Ingress Tool Transfer |
| Tactic | Defense Evasion · Persistence · Command and Control |
| Coverage | Moderate |
| Log source | Endpoint process events |

**Description**: `bitsadmin.exe /transfer` downloads remote files using the BITS service, which bypasses many security controls and can survive reboots. Network artifacts appear in a parallel `svchost.exe` process (not from bitsadmin.exe itself) — examine svchost network connections for the download.

**Pseudocode**:
```
processes = search Process:Create
bitsadmin_transfer = filter processes where (
  exe == "C:\Windows\System32\bitsadmin.exe" AND
  command_line CONTAINS "*transfer*"
)
output bitsadmin_transfer
```

**Splunk**:
```splunk
| tstats count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name=bitsadmin.exe Processes.process=*transfer*
  by Processes.dest Processes.user Processes.parent_process
     Processes.process_name Processes.process
     Processes.process_id Processes.parent_process_id
```

---

### CAR-2021-05-006 — CertUtil Download With URLCache and Split Arguments

| Field | Value |
|---|---|
| ATT&CK | T1105 Ingress Tool Transfer |
| Tactic | Command and Control |
| Coverage | Moderate |
| Log source | Endpoint process events |

**Description**: `certutil.exe -urlcache -f -split <url>` downloads remote content to disk. Legitimate certutil operations against external IPs are rare. Investigate resulting files and reputation of contacted IP/domain. Download artifacts land at the specified path or in `%APPDATA%\..\LocalLow\Microsoft\CryptnetUrlCache\Content\<hash>`.

**Pseudocode**:
```
processes = search Process:Create
certutil_dl = filter processes where (
  exe == "C:\Windows\System32\certutil.exe" AND
  command_line CONTAINS "*urlcache*" AND
  command_line CONTAINS "*split*"
)
output certutil_dl
```

**Splunk**:
```splunk
| tstats count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name=certutil.exe
        Processes.process=*urlcache*
        Processes.process=*split*
  by Processes.dest Processes.user Processes.parent_process
     Processes.process_name Processes.process
     Processes.process_id Processes.parent_process_id
```

---

### CAR-2021-05-007 — CertUtil Download With VerifyCtl and Split Arguments

| Field | Value |
|---|---|
| ATT&CK | T1105 Ingress Tool Transfer |
| Tactic | Command and Control |
| Coverage | Moderate |
| Log source | Endpoint process events |

**Description**: Alternate certutil download variant using `-VerifyCtl -f -split`. Same threat model as CAR-2021-05-006 but different command-line signature. Files cache to `%APPDATA%\..\LocalLow\Microsoft\CryptnetUrlCache\Content\<hash>`. Run both analytics in parallel.

**Pseudocode**:
```
processes = search Process:Create
certutil_dl = filter processes where (
  exe == "C:\Windows\System32\certutil.exe" AND
  command_line CONTAINS "*verifyctl*" AND
  command_line CONTAINS "*split*"
)
output certutil_dl
```

**Splunk**:
```splunk
| tstats count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name=certutil.exe
        Processes.process=*verifyctl*
        Processes.process=*split*
  by Processes.dest Processes.user Processes.parent_process
     Processes.process_name Processes.process
     Processes.process_id Processes.parent_process_id
```

---

## Part 2 — Palantir Alerting and Detection Strategy (ADS) Framework

**Note**: The GitHub repository `palantir/alerting-and-detection-strategy-framework` was removed from GitHub (confirmed 404, September 2026). Content below is drawn from the last known published version of the framework.

**Purpose**: ADS provides a structured template for documenting detection rules so they are reproducible, testable, and operationally useful — not just "query + alert name."

### ADS Document Template Structure

Every ADS document contains these sections in order:

| Section | Purpose |
|---|---|
| **Goal** | One sentence: what behavior is this detecting |
| **Categorization** | ATT&CK tactic/technique mapping |
| **Strategy Abstract** | High-level description of the detection approach |
| **Technical Context** | How the technique works; why the chosen data source captures it |
| **Blind Spots and Assumptions** | What this strategy misses; dependencies that must hold |
| **False Positives** | Expected sources of benign alerts; tuning guidance |
| **Validation** | How to trigger the detection in a safe environment |
| **Priority** | High / Medium / Low with rationale |
| **Loggings** | Required data sources and minimum fields |
| **Implementation** | The actual query or rule (SIEM-specific) |
| **Unit Tests** | Specific test cases with expected outcomes |
| **Response** | Triage steps for responders when this fires |

---

### ADS Example 1 — NTLM Relay Attack Detection

| Field | Value |
|---|---|
| Technique | T1557/001 LLMNR/NBT-NS Poisoning and SMB Relay |
| Tactic | Credential Access · Lateral Movement |
| Priority | High |

**Goal**: Detect NTLM relay attacks where an adversary intercepts an NTLM authentication challenge from one host and relays it to authenticate against a second host.

**Strategy Abstract**: Monitor for authentication events where the source IP of a successful NTLM authentication does not match the IP of the host that initiated the connection. At the network level, look for hosts that relay SMB traffic — a host receives an SMB connection on port 445 and immediately initiates an outbound SMB connection to a third host.

**Technical Context**: Tools like Responder, ntlmrelayx, and Impacket capture NTLM challenges by answering LLMNR/NBT-NS broadcast queries and forwarding the authentication to a target. The relay host is detectable because it appears as both a destination (receiving the initial SMB) and a source (forwarding to the victim) in the same authentication transaction window.

**Loggings Required**:
- Windows Security EventID 4624 (successful logon) with LogonType 3 and AuthenticationPackageName = NTLM
- Windows Security EventID 4648 (explicit credential use)
- Network flow logs for port 445 with timing correlation

**Implementation (Splunk)**:
```splunk
index=wineventlog EventCode=4624 AuthenticationPackageName=NTLM LogonType=3
| eval src=replace(IpAddress, "::ffff:", "")
| stats count by src, ComputerName, TargetUserName, _time
| lookup internal_assets ip as src OUTPUT hostname as src_hostname
| where src != ComputerName AND src_hostname != ""
```

**Blind Spots**: Does not catch NTLM relay to services other than SMB (e.g. LDAP, HTTP). Requires NTLM logging to be enabled (not on by default in all environments). Encrypted SMB (SMB3 + signing) prevents relay but not the initial poisoning.

**False Positives**: Load balancers proxying Windows authentication; applications using NTLM pass-through authentication from an appliance with a different IP than the originating client.

**Validation**: Run Responder + ntlmrelayx in a lab with LLMNR enabled. Trigger a file share browse from a victim to a non-existent host.

---

### ADS Example 2 — DNS Tunneling Detection

| Field | Value |
|---|---|
| Technique | T1071/004 Application Layer Protocol: DNS |
| Tactic | Command and Control · Exfiltration |
| Priority | High |

**Goal**: Detect data exfiltration or C2 communications encoded in DNS query/response traffic.

**Strategy Abstract**: DNS tunneling encodes data in query labels (subdomains) and TXT/NULL responses. It is detectable by statistical anomaly: unusually high query volume from a single host, abnormally long query names, high entropy subdomain labels, and unusual record types (TXT, NULL, MX used for C2).

**Technical Context**: Tools like iodine, dnscat2, and DNSExfiltrator encode binary data as base32/base64 subdomains. A normal workstation generates < 500 DNS queries/day; a tunneling host may generate thousands. Query labels in tunneled traffic have high Shannon entropy (> 3.5 bits/char).

**Loggings Required**:
- DNS query logs with: timestamp, src_ip, query_name, query_type, response_code, response_size
- Zeek `dns.log`: all fields (ts, id.orig_h, query, qtype_name, answers)

**Implementation (Zeek + Splunk)**:
```splunk
sourcetype=zeek:dns
| eval label_length=len(query)
| eval subdomain=replace(query, "\.[^.]+\.[^.]+$", "")
| eval entropy=urldecode(subdomain)  /* approximate via lookup */
| stats count as query_count, avg(label_length) as avg_len, dc(query) as unique_queries
    by id_orig_h, span=1h
| where query_count > 500 OR avg_len > 52 OR unique_queries > 200
```

**Blind Spots**: Slow/low tunneling (< 100 queries/hr) evades volume thresholds. HTTPS-based DNS (DoH) bypasses DNS log visibility entirely. CDN-generated DNS traffic can exceed volume thresholds legitimately.

**False Positives**: WPAD auto-discovery; Windows Update catalog queries; CDN health-check clients; some enterprise security agents with chatty DNS telemetry.

---

### ADS Example 3 — C2 Beaconing via HTTP/HTTPS

| Field | Value |
|---|---|
| Technique | T1071/001 Application Layer Protocol: Web Protocols |
| Tactic | Command and Control |
| Priority | High |

**Goal**: Detect C2 beaconing characterized by periodic, regular HTTP/HTTPS connections from an internal host to an external destination.

**Strategy Abstract**: C2 implants check in at regular intervals (beacon interval + jitter). Statistical detection computes the standard deviation of inter-connection timing per (src_ip, dest_ip, dest_port) tuple. Low standard deviation combined with persistent multi-day activity is anomalous.

**Loggings Required**:
- Zeek `conn.log` or proxy logs with: src_ip, dest_ip, dest_port, timestamp, bytes_out, bytes_in
- Minimum 24-hour window for baseline

**Implementation (RITA-style, Splunk approximation)**:
```splunk
sourcetype=zeek:conn dest_ip!=RFC1918
| bucket _time span=1h
| stats count as hourly_count, sum(bytes_out) as bytes by src_ip, dest_ip, dest_port, _time
| stats stdev(hourly_count) as beacon_score, count as days_seen
    by src_ip, dest_ip, dest_port
| where beacon_score < 2 AND days_seen > 3
| sort beacon_score
```

**Blind Spots**: Jitter > 50% can defeat standard deviation thresholds. Domain-fronting hides the true destination from proxy logs. Long beacon intervals (> 24 hrs) span across day boundaries.

**False Positives**: Software update agents (antivirus, endpoint agents); NTP clients; SNMP polling; monitoring agents with fixed check-in intervals.

---

### ADS Example 4 — WMI-Based Lateral Movement

| Field | Value |
|---|---|
| Technique | T1047 Windows Management Instrumentation |
| Tactic | Execution · Lateral Movement |
| Priority | High |

**Goal**: Detect remote process execution via WMI, which is commonly used by adversaries and C2 frameworks to move laterally without touching disk.

**Strategy Abstract**: Remote WMI uses DCOM over RPC. At the network level, detect RPC connections targeting the IRemUnknown2 interface (port 135) from workstations to workstations. At the host level on the target, detect `WmiPrvSE.exe` spawning unexpected child processes.

**Loggings Required**:
- Network: RPC decode on port 135 with interface UUIDs
- Host: Sysmon EventID 1, parent process = `WmiPrvSE.exe`

**Implementation (Sysmon + Splunk)**:
```splunk
index=sysmon EventCode=1 ParentImage="*\WmiPrvSE.exe"
  NOT (Image="*\WmiApSrv.exe" OR Image="*\scrcons.exe")
| table _time, ComputerName, Image, CommandLine, ParentImage, User
```

---

### ADS Example 5 — Pass-the-Hash Detection

| Field | Value |
|---|---|
| Technique | T1550/002 Use Alternate Authentication Material: Pass the Hash |
| Tactic | Lateral Movement · Defense Evasion |
| Priority | High |

**Goal**: Detect NTLM authentication using a captured password hash without knowing the plaintext password.

**Strategy Abstract**: Pass-the-Hash authentication produces a characteristic event pattern: EventID 4624 (Type 3, NTLM) where the logon comes from a non-standard source process (sekurlsa::pth in Mimikatz spawns a new cmd.exe with a stolen token). Correlate with EventID 4648 and look for NTLM logons from accounts that normally use Kerberos.

**Loggings Required**:
- Windows Security EventID 4624 (Type 3) with NTLM auth package
- Windows Security EventID 4648
- Sysmon EventID 10 (process access to lsass.exe) as precursor

**Implementation (Splunk)**:
```splunk
index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM
  NOT (TargetUserName="ANONYMOUS LOGON" OR TargetUserName="*$")
| stats count by src_ip=IpAddress, TargetUserName, WorkstationName, dest=ComputerName
| where src_ip != dest
```

**Blind Spots**: PtH using Kerberos (overpass-the-hash / pass-the-ticket) is not detected here. Attackers can suppress event 4648 on some configurations. NTLM is required for this detection — environments with NTLMv1/v2 disabled are blind to NTLM-based PtH but also prevent the attack.

---

## Part 3 — Red Canary Top Network-Observable Techniques

**Source**: Red Canary Threat Detection Report 2026 (https://redcanary.com/threat-detection-report/)

The 2026 report reflects a significant shift toward cloud identity abuse, making some traditionally "network" techniques manifest in cloud API logs rather than on-prem netflow.

| Rank | Technique | ID | Network Observability | Notes |
|---|---|---|---|---|
| 1 | Cloud Accounts | T1078.004 | Cloud API audit logs (Azure AD, AWS CloudTrail) | 16x increase year-over-year; identity compromise enabling API abuse |
| 2 | PowerShell | T1059.001 | WinRM/5985 + DNS + HTTP egress | Remote execution produces WinRM network flow; download cradles create HTTP connections |
| 3 | Windows Command Shell | T1059.003 | RDP/3389 or WinRM/5985 | Usually arrives via prior remote access; less direct network signal |
| 4 | Data from Cloud Storage | T1530 | HTTPS to cloud storage endpoints (S3, Azure Blob, GCS) | Exfil via legitimate cloud service APIs; volume + destination anomaly |
| 5 | Ingress Tool Transfer | T1105 | HTTP/HTTPS GET to external IP or CDN | certutil, bitsadmin, curl, PowerShell IWR — all create outbound HTTP |
| 6 | Email Forwarding Rule | T1114.003 | O365/Graph API calls | Adversaries configure mail rules via API after initial cloud account compromise |
| 7 | WMI | T1047 | RPC/135 + dynamic ports (lateral movement) | Internal east-west traffic; see CAR-2014-11-007 |
| 8 | Obfuscated Files / Information | T1027 | Payload delivery over HTTP/HTTPS | Encoded content in web traffic; content-length and entropy anomalies |
| 9 | Email Hiding Rules | T1564.008 | O365 API audit logs | Variant of T1114.003; suppresses sent/received mail to hide BEC activity |
| 10 | BITS Jobs | T1197 | HTTP/HTTPS via svchost.exe BITS | Downloads from external URLs using Windows Update infrastructure ports |

### Red Canary Key Observation: Cloud Identity as Network Pivot

The most network-relevant finding from the 2026 report is that **adversaries increasingly start with cloud identity compromise** (T1078.004) and pivot to on-prem via:
1. VPN or cloud workloads with hybrid connectivity
2. Azure AD Connect sync exploitation
3. Cloud-managed endpoint agents running commands without traditional lateral movement

**Detection implication**: Traditional "east-west netflow" hunting misses this class. Correlate cloud API authentication logs (Azure AD sign-in logs, AWS CloudTrail `AssumeRole`) with unexpected source IPs, geographies, or user agents.

---

## Cross-Reference: ATT&CK Technique Coverage Summary

| ATT&CK ID | Technique | CAR Coverage | ADS Coverage | Red Canary 2026 |
|---|---|---|---|---|
| T1021/001 | RDP | CAR-2013-07-002, CAR-2016-04-005 | — | — |
| T1021/002 | SMB/Admin Shares | CAR-2013-01-003, -05-003, -05-005, -09-003, 2014-03-001 | — | — |
| T1021/006 | WinRM | CAR-2014-11-004, CAR-2014-11-006 | — | — |
| T1040 | Network Sniffing | CAR-2020-11-002 | — | — |
| T1046 | Network Service Discovery | CAR-2021-01-001 | — | — |
| T1047 | WMI | CAR-2014-11-007 | ADS Example 4 | #7 |
| T1070/005 | Network Share Removal | CAR-2020-11-007 | — | — |
| T1071/001 | Web Protocol C2 | — | ADS Example 3 | indirect |
| T1071/004 | DNS C2 | — | ADS Example 2 | — |
| T1078/004 | Cloud Accounts | — | — | #1 (16x increase) |
| T1105 | Ingress Tool Transfer | CAR-2021-05-005, -006, -007 | — | #5 |
| T1187 | Forced Authentication | CAR-2013-09-003 | — | — |
| T1197 | BITS Jobs | CAR-2021-05-005 | — | #10 |
| T1505/003 | Web Shell | CAR-2021-02-001 | — | — |
| T1530 | Data from Cloud Storage | — | — | #4 |
| T1550/002 | Pass the Hash | — | ADS Example 5 | — |
| T1557/001 | NTLM Relay | — | ADS Example 1 | — |
| T1570 | Lateral Tool Transfer | CAR-2013-05-003, -05-005, 2014-03-001 | — | — |

---

## Appendix: Data Sources Required by These Analytics

| Data Source | Analytics Using It | Minimum Fields |
|---|---|---|
| Network flow (port 445) | CAR-2013-01-003, -05-003, -05-005, -09-003, 2014-03-001 | src_ip, dest_ip, dest_port, proto_info (SMB metadata) |
| Network flow (port 3389) | CAR-2013-07-002 | src_ip, dest_ip, dest_port, flow start/end |
| Network flow (port 135) | CAR-2014-05-001, CAR-2014-11-007 | src_ip, dest_ip, dest_port, rpc_interface |
| Network flow (port 5985/5986) | CAR-2014-11-006 | src_ip, dest_ip, dest_port |
| Firewall/netflow logs | CAR-2021-01-001 | src_ip, dest_ip, dest_port |
| Sysmon EventID 1 (process create) | CAR-2014-11-004, -2020-11-002, -2021-02-001, -05-005, -05-006, -05-007 | Image, CommandLine, ParentImage |
| Windows Security EventLog 4624 | CAR-2013-02-012, CAR-2016-04-005, ADS PtH, ADS NTLM Relay | LogonType, AuthPackage, IpAddress, TargetUserName |
| Zeek dns.log | ADS DNS Tunneling | ts, id.orig_h, query, qtype_name, answers |
| Zeek conn.log | ADS C2 Beaconing | ts, id.orig_h, id.resp_h, id.resp_p, orig_bytes, resp_bytes |
| Cloud API audit logs | Red Canary T1078.004, T1114.003, T1530 | actor_ip, action, resource, timestamp, user_agent |
