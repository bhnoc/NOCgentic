# PB-16: OTRF ThreatHunter-Playbook — Network-Observable Techniques

Source: [OTRF/ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook) (master, fetched 2026-09-10)  
Scope: Techniques from the `docs/hunts/windows/` corpus that produce network-observable artifacts, with Zeek/Suricata correlation notes added.

> **Note on data source model:** OTRF playbooks use Windows event log analytics (Security Channel + Sysmon). Network visibility is obtained from Windows Filtering Platform events (5156), authentication logon events (4624 LogonType=3 with IpAddress), and file-share access events (5140/5145 with IpAddress/IpPort). These must be correlated with Zeek conn.log / smb.log / http.log for pure-network hunting when endpoint telemetry is unavailable.

---

## Table of Contents

| # | Hunt ID | Technique | Tactic | Network Protocol |
|---|---------|-----------|--------|-----------------|
| 1 | 190511 | T1059.001 / T1021.006 — PowerShell Remote Session | Execution / Lateral Movement | WinRM (HTTP/5985, HTTPS/5986) |
| 2 | 190810 | T1047 — WMI Win32_Process Remote Execution | Execution / Lateral Movement | DCOM/RPC (TCP 135 + ephemeral) |
| 3 | 190815 | T1569.002 — Remote Service Installation | Execution / Lateral Movement | SMB/svcctl (TCP 445) |
| 4 | 190826 | T1007 — Remote SCM Handle (Admin Discovery) | Discovery | SMB (TCP 445) |
| 5 | 201012 | T1021.002 — SMB Create Remote File | Lateral Movement | SMB (TCP 445) |
| 6 | 200902 | T1546.003 — Remote WMI ActiveScriptEventConsumers | Persistence / Lateral Movement | DCOM/RPC (TCP 135 + ephemeral) |
| 7 | 201009a | T1021.003 — Remote DCOM IErtUtil DLL Hijack | Lateral Movement | SMB (TCP 445) + DCOM |
| 8 | 201009b | T1021.003 — Remote WMI Wbemcomn DLL Hijack | Lateral Movement | SMB (TCP 445) + DCOM |
| 9 | 180815 | T1003.006 — DCSync (AD Object Access Replication) | Credential Access | MS-DRSR / RPC (TCP 135 + ephemeral, or TCP 49152+) |
| 10 | 190101 | T1484 / T1078 — AD Root Domain Modification for Replication | Defense Evasion | LDAP (TCP 389) |
| 11 | 190620 | T1555 / T1003 — Domain DPAPI Backup Key Extraction | Credential Access | SMB/lsarpc (TCP 445) |
| 12 | 191224 | T1112 — Extended NetNTLM Downgrade | Defense Evasion | SMB/NTLM (TCP 445) |
| 13 | 190407 | T1112 — Registry Modification to Enable RDP | Defense Evasion | RDP (TCP 3389) |

---

## 1. PowerShell Remote Session

**Hunt ID:** 190511-RemotePwshExecution  
**ATT&CK:** T1059.001 (PowerShell), T1021.006 (Windows Remote Management)  
**Tactics:** TA0002 Execution, TA0008 Lateral Movement  
**Dataset:** [Empire PSRemoting](https://securitydatasets.com/notebooks/atomic/windows/execution/SDWIN-190518211456.html)

### Hypothesis
Adversaries might be leveraging remote PowerShell sessions via WinRM to execute code on remote systems.

### Network Protocol
Windows Remote Management (WinRM) over HTTP (TCP 5985) or HTTPS (TCP 5986). The remote session host process is `wsmprovhost.exe`.

### Detection Logic

**Analytic I — PowerShell host initialization (Event Log):**
```sql
SELECT @timestamp, Hostname, Channel
FROM dataTable
WHERE (Channel = 'Microsoft-Windows-PowerShell/Operational' OR Channel = 'Windows PowerShell')
  AND (EventID = 400 OR EventID = 4103)
  AND Message LIKE '%HostApplication%wsmprovhost%'
```
Data sources: PowerShell Operational log events 400 / 4103.

**Analytic II — Incoming WinRM network connection (Windows Filtering Platform):**
```sql
SELECT @timestamp, Hostname, Application, SourceAddress, DestAddress, LayerName, LayerRTID
FROM dataTable
WHERE LOWER(Channel) = 'security'
  AND EventID = 5156
  AND (DestPort = 5985 OR DestPort = 5986)
  AND LayerRTID = 44
```
Data sources: Security Event 5156 (WFP permitted connection).

**Analytic III — wsmprovhost.exe process chain (Security Audit):**
```sql
SELECT @timestamp, Hostname, ParentProcessName, NewProcessName
FROM dataTable
WHERE LOWER(Channel) = 'security'
  AND EventID = 4688
  AND (ParentProcessName LIKE '%wsmprovhost.exe' OR NewProcessName LIKE '%wsmprovhost.exe')
```

**Analytic IV — Sysmon network connection outbound (not NETWORK SERVICE / SYSTEM):**
```sql
SELECT @timestamp, Hostname, User, Initiated, Image, SourceIp, DestinationIp
FROM dataTable
WHERE Channel = 'Microsoft-Windows-Sysmon/Operational'
  AND EventID = 3
  AND (DestinationPort = 5985 OR DestinationPort = 5986)
  AND NOT User IN ('NT AUTHORITY\\NETWORK SERVICE', 'NT AUTHORITY\\SYSTEM')
```
Data sources: Sysmon Event 3 (network connection).

### Zeek Correlation
- `conn.log`: filter `id.resp_p == 5985 OR id.resp_p == 5986` — WinRM is HTTP/SOAP over port 5985; connections from workstation to workstation (not server) are suspicious.
- `http.log`: WinRM uses SOAP/XML over HTTP. Look for `uri` containing `/wsman` and `method = "POST"`.
- `ssl.log`: Port 5986 will show TLS; cross-reference cert CN against expected infrastructure.
- Anomaly: workstation-to-workstation WinRM connections are abnormal in most environments.

### Key Indicators
- wsmprovhost.exe as parent of spawned processes
- Destination ports 5985 / 5986 from non-server endpoints
- PowerShell events 400/4103 with `HostApplication=wsmprovhost`
- Windows Filtering Platform Event 5156 on ports 5985/5986

---

## 2. WMI Remote Execution (Win32_Process.Create)

**Hunt ID:** 190810-RemoteWMIExecution  
**ATT&CK:** T1047 (Windows Management Instrumentation)  
**Tactics:** TA0002 Execution, TA0008 Lateral Movement  
**Dataset:** [Empire Invoke WMI](https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-200921001437.html)

### Hypothesis
Adversaries might be leveraging WMI Win32_Process.Create to execute code on remote systems via DCOM/RPC.

### Network Protocol
DCOM: initial connection to TCP 135 (endpoint mapper), then dynamic high port (49152+). The remote process is spawned under `WmiprvSE.exe` in a LogonType=3 session.

### Detection Logic

**Analytic I — wmiprvse.exe spawning non-system processes (Security Audit 4688):**
```sql
SELECT @timestamp, Hostname, SubjectUserName, TargetUserName, NewProcessName, CommandLine
FROM dataTable
WHERE LOWER(Channel) = 'security'
  AND EventID = 4688
  AND LOWER(ParentProcessName) LIKE '%wmiprvse.exe'
  AND NOT TargetLogonId = '0x3e7'
```

**Analytic II — Sysmon process creation (Event 1):**
```sql
SELECT @timestamp, Hostname, User, Image, CommandLine
FROM dataTable
WHERE Channel = 'Microsoft-Windows-Sysmon/Operational'
  AND EventID = 1
  AND LOWER(ParentImage) LIKE '%wmiprvse.exe'
  AND NOT LogonId = '0x3e7'
```

**Analytic III — Correlate process creation with source IP via LogonType=3 (Network Logon):**
```sql
SELECT o.@timestamp, o.Hostname, o.SubjectUserName, o.TargetUserName, o.NewProcessName, o.CommandLine, a.IpAddress
FROM dataTable o
INNER JOIN (
  SELECT Hostname, TargetUserName, TargetLogonId, IpAddress
  FROM dataTable
  WHERE LOWER(Channel) = 'security'
    AND EventID = 4624
    AND LogonType = 3
    AND NOT TargetUserName LIKE '%$'
) a ON o.TargetLogonId = a.TargetLogonId
WHERE LOWER(o.Channel) = 'security'
  AND o.EventID = 4688
  AND LOWER(o.ParentProcessName) LIKE '%wmiprvse.exe'
```
This join surfaces the originating IP address of the WMI call.

### Zeek Correlation
- `conn.log`: connections to TCP 135 (DCE/RPC endpoint mapper) followed by connections to high ephemeral ports from the same source IP; lateral-movement pattern is SYN to 135, then SYN to 49152+.
- `dce_rpc.log` (Zeek): look for endpoint `IWbemServices` and operation `ExecMethod` or `ExecMethodAsync`.
- Zeek package `zeek-dce-rpc` surfaces interface UUIDs — WMI uses `6bffd098-a112-3610-9833-46c3f87e345a` (IWbemServices).

### Key Indicators
- wmiprvse.exe as parent process (LogonType=3 session, not 0x3e7 SYSTEM)
- Network logon (Event 4624 LogonType=3) correlated with subsequent process creation under wmiprvse
- DCOM traffic: TCP 135 + ephemeral port pair from a workstation to another workstation

---

## 3. Remote Service Installation (PsExec pattern)

**Hunt ID:** 190815-RemoteServiceInstallation  
**ATT&CK:** T1569.002 (Service Execution)  
**Tactics:** TA0002 Execution, TA0008 Lateral Movement  
**Dataset:** [Empire Invoke PsExec](https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-190518210652.html)

### Hypothesis
Adversaries might be creating new services remotely (PsExec/svcctl) to execute code and move laterally.

### Network Protocol
SMB (TCP 445) using the `svcctl` named pipe. Traffic pattern: connect to `\\target\IPC$`, open `\svcctl` pipe, call `CreateService`.

### Detection Logic

**Analytic I — New service in a network logon session (correlate 4697 + 4624):**
```sql
SELECT o.@timestamp, o.Hostname, o.SubjectUserName, o.ServiceName, a.IpAddress
FROM dataTable o
INNER JOIN (
  SELECT Hostname, TargetUserName, TargetLogonId, IpAddress
  FROM dataTable
  WHERE LOWER(Channel) = 'security'
    AND EventID = 4624
    AND LogonType = 3
    AND NOT TargetUserName LIKE '%$'
) a ON o.SubjectLogonId = a.TargetLogonId
WHERE LOWER(o.Channel) = 'security'
  AND o.EventID = 4697
```
Event 4697 = service installed. Join on LogonId gives the source IP.

### Zeek Correlation
- `smb.log` / `dce_rpc.log`: `svcctl` pipe calls; Zeek's SMB analyzer surfaces named pipe traffic.
- `conn.log`: connection from attacker to victim on TCP 445 prior to service install time (correlate timestamp).
- `files.log`: PsExec drops a binary (PSEXESVC.exe) via SMB — will appear in `files.log` with `source = SMB`.
- Look for `smb_files.log` entries where `action = SMB::FILE_OPEN` and `name` matches `PSEXESVC` or unusual service names.

### Key Indicators
- Event 4697 (service created) + Event 4624 LogonType=3 (network logon) with same LogonId
- Source IP from the 4624 event reveals attacker's lateral origin
- SMB file write followed by service creation within seconds
- Service executable in temp/unusual paths

---

## 4. Remote SCM Handle (Local Admin Discovery)

**Hunt ID:** 190826-RemoteSCMHandle  
**ATT&CK:** T1007 (System Service Discovery)  
**Tactic:** TA0007 Discovery  
**Dataset:** [Empire Find Local Admin](https://securitydatasets.com/notebooks/atomic/windows/discovery/SDWIN-190518224039.html)

### Hypothesis
Adversaries might be opening a handle to the remote Service Control Manager to enumerate local admin access across the network.

### Network Protocol
SMB (TCP 445) + RPC; `OpenSCManagerA` call over `\svcctl` named pipe returns non-zero handle if caller has local admin.

### Detection Logic

**Analytic I — SCM object handle request with FULL_ACCESS mask:**
```sql
SELECT @timestamp, Hostname, SubjectUserName, ProcessName, ObjectName
FROM dataTable
WHERE LOWER(Channel) = 'security'
  AND EventID = 4656
  AND ObjectType = 'SC_MANAGER OBJECT'
  AND ObjectName = 'ServicesActive'
  AND AccessMask = '0xf003f'
  AND NOT SubjectLogonId = '0x3e4'
```
Event 4656 = object handle requested. AccessMask 0xf003f = SC_MANAGER_ALL_ACCESS.

**Analytic II — Privileged operations on SCM object:**
```sql
SELECT @timestamp, Hostname, SubjectUserName, ProcessName, ObjectName
FROM dataTable
WHERE LOWER(Channel) = 'security'
  AND EventID = 4674
  AND ObjectType = 'SC_MANAGER OBJECT'
  AND ObjectName = 'ServicesActive'
  AND NOT SubjectLogonId = '0x3e4'
```
Event 4674 = privileged operation attempted on an object.

### Zeek Correlation
- `dce_rpc.log`: `svcctl` interface with `OpenSCManagerA` / `OpenSCManagerW` operation.
- `conn.log`: scanning pattern — rapid sequential TCP 445 connections from a single source to many destinations within a short window; each connection tests local admin via SCM.
- High connection count to TCP 445 from a single workstation is a key indicator.

### Key Indicators
- Event 4656 (ObjectType=SC_MANAGER, AccessMask=0xf003f) from non-machine-account sessions
- Event 4674 on ServicesActive object
- Fan-out SMB connections from a single host across many targets (admin enumeration pattern)

---

## 5. SMB Create Remote File

**Hunt ID:** 201012-RemoteCreateFileSMB  
**ATT&CK:** T1021.002 (SMB/Windows Admin Shares)  
**Tactic:** TA0008 Lateral Movement  
**Dataset:** [Covenant SMB File Copy](https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-200806015757.html)

### Hypothesis
Adversaries might be creating files remotely via SMB (e.g., copying binaries to admin shares C$ for later execution).

### Network Protocol
SMB (TCP 445), specifically SMB2 CREATE request to administrative shares (C$, ADMIN$).

### Detection Logic

**Analytic I — Non-system account tree connect to non-IPC$ share:**
```sql
SELECT @timestamp, Hostname, ShareName, SubjectUserName, SubjectLogonId, AccessMask
FROM dataTable
WHERE LOWER(Channel) = 'security'
  AND EventID = 5140
  AND NOT ShareName LIKE '%IPC$'
  AND NOT SubjectUserName LIKE '%$'
```
Event 5140 = network share accessed.

**Analytic II — Same logon session connects to IPC$ then C$ (PsExec/lateral pattern):**
```sql
SELECT @timestamp, Hostname, ShareName, SubjectUserName, b.SubjectLogonId, IpAddress, IpPort
FROM dataTable b
INNER JOIN (
  SELECT SubjectLogonId
  FROM dataTable
  WHERE LOWER(Channel) = 'security'
    AND EventID = 5140
    AND ShareName LIKE '%IPC$'
    AND NOT SubjectUserName LIKE '%$'
) a ON b.SubjectLogonId = a.SubjectLogonId
WHERE LOWER(b.Channel) = 'security'
  AND b.EventID = 5140
  AND b.ShareName LIKE '%C$'
  AND NOT SubjectUserName LIKE '%$'
```

**Analytic III — File write with AccessMask=0x2 to admin share (actual file creation):**
```sql
SELECT @timestamp, Hostname, ShareName, SubjectUserName, SubjectLogonId, IpAddress, IpPort, RelativeTargetName
FROM dataTable
WHERE LOWER(Channel) = 'security'
  AND EventID = 5145
  AND ShareName LIKE '%C$'
  AND NOT SubjectUserName LIKE '%$'
  AND AccessMask = '0x2'
```
Event 5145 = network share file/object access checked. AccessMask 0x2 = write.

### Zeek Correlation
- `smb_files.log`: `action = SMB::FILE_OPEN` with `name` containing paths in `C$\Windows\Temp` or `C$\Users` from a non-server source.
- `conn.log`: SMB connection (TCP 445) from workstation to workstation — lateral.
- `files.log`: binary file types (PE32) transferred over SMB.
- Zeek `smb.log` surfaces the share path (`tree`), which directly maps to the ShareName field.

### Key Indicators
- Event 5140 (IPC$ + C$ from same LogonId in rapid succession)
- Event 5145 AccessMask=0x2 on C$ path
- IpAddress/IpPort fields in events reveal the originating host
- SMB file write of executable content (PE headers visible in packet capture)

---

## 6. Remote WMI ActiveScriptEventConsumers

**Hunt ID:** 200902-RemoteWMIActiveScriptEventConsumers  
**ATT&CK:** T1546.003 (Windows Management Instrumentation Event Subscription)  
**Tactics:** TA0003 Persistence, TA0004 Privilege Escalation, TA0008 Lateral Movement  
**Dataset:** [Covenant WMI Remote Eventing](https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-200724174200.html)

### Hypothesis
Adversaries might be leveraging WMI ActiveScriptEventConsumers remotely to achieve persistence/lateral movement with SYSTEM execution.

### Network Protocol
DCOM/RPC (TCP 135 + ephemeral); WMI subscription created remotely via `IWbemServices`.

### Detection Logic

**Analytic I — Sysmon WMI consumer creation (type: script):**
```sql
SELECT EventID, EventType
FROM dataTable
WHERE Channel = 'Microsoft-Windows-Sysmon/Operational'
  AND EventID = 20
  AND LOWER(Message) LIKE '%type: script%'
```
Sysmon Event 20 = WMI event consumer activity.

**Analytic II — WMI operational log subscription created with VBScript engine:**
```sql
SELECT EventID, SourceName
FROM dataTable
WHERE Channel = 'Microsoft-Windows-WMI-Activity/Operational'
  AND EventID = 5861
  AND LOWER(Message) LIKE '%scriptingengine = "vbscript"%'
```
Event 5861 = permanent WMI event subscription.

### Zeek Correlation
- Same as entry 2 (WMI Remote Execution): DCOM traffic to TCP 135 + dynamic port.
- Distinguish from regular WMI by looking for longer-lived connections (subscription registration keeps the session open).
- Zeek `dce_rpc.log`: `IWbemServices` interface, operations `PutInstance` (creating the consumer/filter objects) and `ExecMethod`.

### Key Indicators
- Sysmon Event 20 (WMI consumer) + Event 19 (WMI filter) + Event 21 (filter-consumer binding) in rapid sequence
- VBScript or JScript engine specified in consumer
- Remote DCOM source IP combined with WMI subscription creation timestamp

---

## 7. Remote DCOM IErtUtil DLL Hijack

**Hunt ID:** 201009-RemoteDCOMIErtUtilDLLHijack  
**ATT&CK:** T1021.003 (Distributed Component Object Model)  
**Tactic:** TA0008 Lateral Movement  
**Dataset:** [Covenant DCOM Iertutil DLL Hijack](https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-201009183000.html)

### Hypothesis
Threat actors might copy a malicious `iertutil.dll` via SMB to `C:\Program Files\Internet Explorer\`, then trigger it by instantiating `InternetExplorer.Application` DCOM object remotely.

### Network Protocol
SMB (TCP 445) for DLL staging + DCOM (TCP 135 + ephemeral) for trigger.

### Detection Logic

**Analytic I — SMB write to iertutil.dll path with AccessMask=write:**
```sql
SELECT @timestamp, Hostname, ShareName, SubjectUserName, SubjectLogonId, IpAddress, IpPort, RelativeTargetName
FROM dataTable
WHERE LOWER(Channel) = 'security'
  AND EventID = 5145
  AND RelativeTargetName LIKE '%Internet Explorer\iertutil.dll'
  AND NOT SubjectUserName LIKE '%$'
  AND AccessMask = '0x2'
```

**Analytic II — Cross-correlate SMB write and Sysmon file creation:**
Join Event 5145 (SMB write to iertutil.dll) with Sysmon Event 11 (FileCreate targeting the same path) created by SYSTEM — confirms the file was written via the network and created locally.

### Zeek Correlation
- `smb_files.log`: `name` ending in `iertutil.dll` from a remote source.
- `files.log`: DLL file type (PE/DLL magic bytes) written over SMB from external source.
- DCOM trigger: TCP 135 + ephemeral from same source IP shortly after the SMB write.

### Key Indicators
- SMB write (Event 5145) to `%Program Files%\Internet Explorer\iertutil.dll`
- Source IP matches subsequent DCOM connection
- DLL file appearing in IE directory via network file write (unusual — no installer should write there over SMB)

---

## 8. Remote WMI Wbemcomn DLL Hijack

**Hunt ID:** 201009-RemoteWMIWbemcomnDLLHijack  
**ATT&CK:** T1021.003 (Distributed Component Object Model)  
**Tactic:** TA0008 Lateral Movement  
**Dataset:** [Covenant WMI Wbemcomn DLL Hijack](https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-201009173318.html)

### Hypothesis
Threat actors might copy a malicious `wbemcomn.dll` to `C:\Windows\System32\wbem\` via SMB, triggering it when `wmiprvse.exe` loads it (executes as NETWORK SERVICE).

### Network Protocol
SMB (TCP 445) for DLL staging + DCOM/RPC for WMI trigger.

### Detection Logic

**Analytic I — SMB write to wbemcomn.dll path:**
```sql
SELECT @timestamp, Hostname, ShareName, SubjectUserName, SubjectLogonId, IpAddress, IpPort, RelativeTargetName
FROM dataTable
WHERE LOWER(Channel) = 'security'
  AND EventID = 5145
  AND RelativeTargetName LIKE '%wbem\wbemcomn.dll'
  AND NOT SubjectUserName LIKE '%$'
  AND AccessMask = '0x2'
```

### Zeek Correlation
- `smb_files.log`: `name` matching `wbemcomn.dll` written from a remote host.
- Same DCOM follow-on pattern as entry 7.

### Key Indicators
- Network write of `wbemcomn.dll` into `C:\Windows\System32\wbem\` via SMB
- SYSTEM-context DLL load from wmiprvse.exe following the write
- Execution as NETWORK SERVICE after the hijack

---

## 9. DCSync — AD Object Access Replication

**Hunt ID:** 180815-ADObjectAccessReplication  
**ATT&CK:** T1003.006 (DCSync) [formerly covered under credential access]  
**Tactic:** TA0006 Credential Access  
**Dataset:** [AD Replication Attack](https://securitydatasets.com/notebooks/atomic/windows/credential_access/)

### Hypothesis
Adversaries (with domain admin or equivalent) might use DCSync (Mimikatz `lsadump::dcsync`) to request replication of password hashes from a domain controller without a process running on the DC.

### Network Protocol
MS-DRSR (Directory Replication Service Remote Protocol) over MSRPC, typically TCP 135 + dynamic port to DC. Can also traverse TCP 49152-65535. The source is a non-DC machine.

### Detection Logic

**Analytic I — AD replication access by non-machine account (Event 4662 with DS-Replication GUIDs):**
```sql
SELECT @timestamp, Hostname, SubjectUserName, SubjectLogonId
FROM dataTable
WHERE LOWER(Channel) = 'security'
  AND EventID = 4662
  AND AccessMask = '0x100'
  AND (
    Properties LIKE '%1131f6aa_9c07_11d1_f79f_00c04fc2dcd2%'
    OR Properties LIKE '%1131f6ad_9c07_11d1_f79f_00c04fc2dcd2%'
    OR Properties LIKE '%89e95b76_444d_4c62_991a_0facbeda640c%'
  )
  AND NOT SubjectUserName LIKE '%$'
```

GUIDs:
- `1131f6aa-...` = DS-Replication-Get-Changes
- `1131f6ad-...` = DS-Replication-Get-Changes-All (required for password hash sync)
- `89e95b76-...` = DS-Replication-Get-Changes-In-Filtered-Set

**Analytic II — Correlate replication access with network logon to find source IP:**
```sql
SELECT o.@timestamp, o.Hostname, o.SubjectUserName, o.SubjectLogonId, a.IpAddress
FROM dataTable o
INNER JOIN (
  SELECT Hostname, TargetUserName, TargetLogonId, IpAddress
  FROM dataTable
  WHERE LOWER(Channel) = 'security'
    AND EventID = 4624
    AND LogonType = 3
    AND NOT TargetUserName LIKE '%$'
) a ON o.SubjectLogonId = a.TargetLogonId
WHERE LOWER(o.Channel) = 'security'
  AND o.EventID = 4662
  AND o.AccessMask = '0x100'
  AND (o.Properties LIKE '%1131f6aa%' OR o.Properties LIKE '%1131f6ad%')
  AND o.Hostname = a.Hostname
  AND NOT o.SubjectUserName LIKE '%$'
```

### Zeek Correlation
- `conn.log`: RPC traffic from a non-DC machine to the DC on TCP 49152+ (DRSUAPI lives here); DCSync does NOT hit TCP 445 — it uses RPC.
- `dce_rpc.log` (if captured): Interface UUID `e3514235-4b06-11d1-ab04-00c04fc2dcd2` (MS-DRSR / DRSUAPI). Operation `DRSGetNCChanges` is the actual hash-pull call.
- Anomaly: DRSUAPI calls from any host other than a domain controller are essentially always suspicious.
- Zeek `weird.log` may fire if non-standard DRSUAPI implementations are used.

### Key Indicators
- Event 4662 on DC with DS-Replication-Get-Changes-All GUID from a non-machine account
- Source IP (from 4624 LogonType=3 join) is a workstation, not a DC
- DRSUAPI interface traffic (`e3514235-4b06-11d1-ab04-00c04fc2dcd2`) in network captures from non-DC sources
- Tools: Mimikatz `lsadump::dcsync`, Impacket `secretsdump.py`

---

## 10. AD Root Domain Modification for Replication (Skeleton DCSync Setup)

**Hunt ID:** 190101-ADModDirectoryReplication  
**ATT&CK:** T1484 (Domain Policy Modification), T1078 (Valid Accounts)  
**Tactic:** TA0005 Defense Evasion  
**Dataset:** OTRF AD Replication Dataset

### Hypothesis
Adversaries with domain admin rights might add DS-Replication ACLs to a regular user account to bypass detections that only look for known privileged accounts performing DCSync.

### Network Protocol
LDAP (TCP 389 / LDAPS TCP 636) for ACL modification; then DRSUAPI (TCP 135 + ephemeral) once replication is invoked.

### Detection Logic

**Analytic I — User accessing directory service objects with replication GUID (Event 4662):**
```sql
SELECT @timestamp, Hostname, SubjectUserName, ObjectName, OperationType
FROM dataTable
WHERE LOWER(Channel) = 'security'
  AND EventID = 4662
  AND ObjectServer = 'DS'
  AND AccessMask = '0x40000'
  AND ObjectType LIKE '%19195a5b_6da0_11d0_afd3_00c04fd930c9%'
```
ObjectType GUID `19195a5b-6da0-11d0-afd3-00c04fd930c9` = Domain DNS.

**Analytic II — ACL modification on AD objects with replication rights (Event 5136):**
```sql
SELECT @timestamp, Hostname, SubjectUserName, ObjectDN, AttributeLDAPDisplayName
FROM dataTable
WHERE LOWER(Channel) = 'security'
  AND EventID = 5136
  AND AttributeLDAPDisplayName = 'nTSecurityDescriptor'
```
Event 5136 = directory service object modified. Modification to `nTSecurityDescriptor` on the domain root = ACL change that can grant replication rights.

### Zeek Correlation
- `dce_rpc.log`: LDAP operations on DC (port 389) modifying ACLs — Zeek's LDAP analyzer can surface this.
- Combination: LDAP write to domain root nTSecurityDescriptor followed within minutes by DRSUAPI traffic from the same (now-granted) user.

### Key Indicators
- Event 5136 (nTSecurityDescriptor modified on domain root) by domain admin account
- Subsequent DCSync (Events from entry 9) by a previously non-privileged user
- LDAP write to domain partition root object followed by replication traffic

---

## 11. Domain DPAPI Backup Key Extraction

**Hunt ID:** 190620-DomainDPAPIBackupKeyExtraction  
**ATT&CK:** T1555, T1003 (Credential Access via LSA secrets)  
**Tactic:** TA0006 Credential Access  
**Dataset:** [Empire Mimikatz Backupkeys](https://securitydatasets.com/notebooks/atomic/windows/credential_access/SDWIN-190518235535.html)

### Hypothesis
Adversaries with domain admin privileges might extract the DPAPI domain backup key (using Mimikatz `lsadump::backupkeys`) to decrypt all domain users' protected credentials offline.

### Network Protocol
SMB (TCP 445) using the `\pipe\lsarpc` named pipe on the DC. Mimikatz uses `LsaOpenPolicy` / `LsaRetrievePrivateData` API over MS-LSAD protocol.

### Detection Logic

**Analytic I — Access to BCKUPKEY LSA secret object (Event 4662):**
```sql
SELECT @timestamp, Hostname, ObjectServer, ObjectType, ObjectName
FROM dataTable
WHERE LOWER(Channel) = 'security'
  AND EventID = 4662
  AND AccessMask = '0x2'
  AND LOWER(ObjectName) LIKE '%bckupkey%'
```
ObjectName `G$BCKUPKEY_PREFERRED` or `G$BCKUPKEY_P` = the domain DPAPI backup key.

**Analytic II — Correlate BCKUPKEY access with network logon to find source IP:**
```sql
SELECT o.@timestamp, o.Hostname, o.ObjectName, a.IpAddress
FROM dataTable o
INNER JOIN (
  SELECT Hostname, TargetUserName, TargetLogonId, IpAddress
  FROM dataTable
  WHERE LOWER(Channel) = 'security'
    AND EventID = 4624
    AND LogonType = 3
    AND NOT TargetUserName LIKE '%$'
) a ON o.SubjectLogonId = a.TargetLogonId
WHERE LOWER(Channel) = 'security'
  AND o.EventID = 4662
  AND o.AccessMask = '0x2'
  AND LOWER(o.ObjectName) LIKE '%bckupkey%'
  AND o.Hostname = a.Hostname
```

### Zeek Correlation
- `smb.log` / `dce_rpc.log`: `\pipe\lsarpc` named pipe on DC (TCP 445); operation `LsarRetrievePrivateData` with key name `G$BCKUPKEY_PREFERRED`.
- `conn.log`: SMB connection from attacker workstation to DC (TCP 445) correlated with BCKUPKEY access time.
- Impacket `dpapi.py` and Mimikatz's `backupkeys` module both use the MS-BKRP or MS-LSAD interface over `\pipe\lsarpc`.

### Key Indicators
- Event 4662 with ObjectName containing `BCKUPKEY` (write/read access, AccessMask 0x2)
- Source IP from LogonType=3 4624 join = attacker's workstation
- Named pipe `lsarpc` access on a DC from a non-DC workstation at an unusual time
- Tools: Mimikatz `lsadump::backupkeys`, Impacket `dpapi.py`

---

## 12. Extended NetNTLM Downgrade

**Hunt ID:** 191224-RegModExtendedNetNTLMDowngrade  
**ATT&CK:** T1112 (Modify Registry)  
**Tactic:** TA0005 Defense Evasion  
**Dataset:** [Empire Monologue NetNTLM Downgrade](https://securitydatasets.com/notebooks/atomic/windows/defense_evasion/SDWIN-191225045202.html)

### Hypothesis
Adversaries with local admin rights might modify NTLM authentication registry keys to downgrade from NTLMv2 to NetNTLMv1, enabling capture of weaker hashes via a rogue SMB server (e.g., Responder).

### Registry Keys Targeted
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` → `LMCompatibilityLevel` (set to 0 or 1)
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0` → `NtlmMinClientSec` and `RestrictSendingNTLMTraffic` (set to 0)

### Detection Logic

**Analytic I — Non-LSASS process accessing LSA registry keys:**
```sql
SELECT @timestamp, Hostname, SubjectUserName, ProcessName, ObjectName, AccessMask, EventID, SubjectLogonId
FROM dataTable
WHERE LOWER(Channel) = 'security'
  AND EventID IN (4663, 4656)
  AND ObjectType = 'Key'
  AND (ObjectName LIKE '%Lsa' OR ObjectName LIKE '%Lsa\MSV1_0')
  AND ProcessName NOT LIKE '%lsass.exe'
  AND SubjectLogonId != '0x3e7'
```

**Analytic II — Specific registry value modifications (Sysmon Event 13):**
Look for Sysmon Event 13 (registry value set) targeting:
- `LMCompatibilityLevel`
- `NtlmMinClientSec`
- `RestrictSendingNTLMTraffic`

### Zeek Correlation (Downstream Effect)
- After downgrade, the host will send NTLMv1 challenge responses instead of NTLMv2.
- `ntlm.log` (Zeek): if Zeek captures NTLM traffic, look for `ntlm_version = 1` in authentication exchanges from the compromised host.
- NTLM downgrade is only detectable in network traffic once the host actually authenticates; the registry change itself is host-based.
- Suricata rule: detect NTLM Auth messages with NTLMv1 flags (`NTLMSSP_NEGOTIATE_LM_KEY` set, `NTLMSSP_NEGOTIATE_NTLM` without extended security).

### Key Indicators
- Registry modification to `LMCompatibilityLevel` = 0 or 1 (not the default 3 or 5)
- `NtlmMinClientSec` set to 0 (removes requirement for message signing/sealing)
- `RestrictSendingNTLMTraffic` set to 0 (re-enables NTLM to arbitrary servers)
- Downstream: NTLMv1 responses in network captures; Zeek `ntlm.log` version indicators

---

## 13. Registry Modification to Enable RDP

**Hunt ID:** 190407-RegModEnableRDPConnections  
**ATT&CK:** T1112 (Modify Registry)  
**Tactic:** TA0005 Defense Evasion  
**Dataset:** [Empire Enable RDP](https://securitydatasets.com/notebooks/atomic/windows/defense_evasion/SDWIN-190518203650.html)

### Hypothesis
Adversaries might modify registry keys to enable Remote Desktop connections on a host where RDP is disabled, preparing for subsequent lateral movement.

### Registry Keys Targeted
- `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections` = 0 (enable RDP)
- `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication` = 0 (disable NLA)

### Detection Logic

**Analytic I — Process modifying fDenyTSConnections or UserAuthentication (Sysmon Event 13):**
```sql
SELECT @timestamp, Hostname, Image, TargetObject
FROM dataTable
WHERE Channel = 'Microsoft-Windows-Sysmon/Operational'
  AND EventID = 13
  AND (
    TargetObject LIKE '%fDenyTSConnections'
    OR TargetObject LIKE '%UserAuthentication'
  )
  AND Details = 'DWORD (0x00000000)'
```
Event 13 = registry value set. Details = 0x00000000 = enable RDP / disable NLA.

### Zeek Correlation
- This detection is pre-attack (the registry change enables RDP before it's used).
- Network correlation: after the registry change, watch for new TCP 3389 connections to the modified host.
- `conn.log`: first connection to TCP 3389 on a host that had no prior RDP traffic = strong indicator.
- `ssl.log`: RDP uses TLS (CredSSP/NLA) — certificate fingerprint on port 3389 from an endpoint that recently changed its RDP policy.
- Zeek RDP analyzer: `rdp.log` surfaces RDP negotiation details including security protocol.

### Key Indicators
- Sysmon Event 13 on `fDenyTSConnections` or `UserAuthentication` = 0x0
- First-ever TCP 3389 inbound connection to that host following the registry change
- `UserAuthentication = 0` disabling NLA means no Kerberos pre-auth — watch for successful RDP login without NLA in `rdp.log` / `ssl.log`
- RDP certificate mismatch on the newly-enabled host (self-signed cert where enterprise PKI cert expected)

---

## Cross-Reference: Zeek Log Types by Hunt

| Zeek Log | Relevant Hunts | What It Surfaces |
|----------|---------------|-----------------|
| `conn.log` | All | Source/dest IP, port, bytes, duration — backbone for every lateral technique |
| `smb_files.log` | 3, 5, 7, 8, 11 | File names, paths, SMB operations (OPEN, CREATE, WRITE) over port 445 |
| `dce_rpc.log` | 2, 6, 7, 9, 10, 11 | RPC interface UUID + operation name — identifies DRSUAPI, svcctl, IWbemServices |
| `http.log` | 1 | WinRM SOAP/XML over HTTP on port 5985 (`uri` = `/wsman`) |
| `ssl.log` | 1, 13 | TLS on WinRM (5986) and RDP (3389) — cert fingerprints |
| `ntlm.log` | 12 | NTLM challenge/response version — detects NTLMv1 after downgrade |
| `rdp.log` | 13 | RDP negotiation, security protocol (NLA vs. classic) |
| `files.log` | 3, 5, 7, 8 | PE/DLL files transferred over SMB |
| `weird.log` | 9 | Protocol anomalies in DRSUAPI from unexpected sources |

---

## Cross-Reference: Key Windows Events for Network Lateral Movement

| Event ID | Provider | What It Records | Used In |
|----------|----------|----------------|---------|
| 4624 (LogonType=3) | Security | Network logon with source IP | 2, 3, 5, 9, 11 |
| 4656 | Security | Object handle requested | 4 |
| 4662 | Security | AD object accessed (replication GUIDs, BCKUPKEY) | 9, 10, 11 |
| 4674 | Security | Privileged operation on object | 4 |
| 4688 | Security | Process creation (with ParentProcessName) | 1, 2, 3 |
| 4697 | Security | Service installed | 3 |
| 5136 | Security | AD object modified (nTSecurityDescriptor) | 10 |
| 5140 | Security | Network share accessed (IPC$, C$) | 5 |
| 5145 | Security | Network share object access checked (file-level, with IpAddress) | 5, 7, 8 |
| 5156 | Security | WFP permitted connection (destination port) | 1 |
| 13 (Sysmon) | Sysmon | Registry value set | 12, 13 |
| 20 (Sysmon) | Sysmon | WMI event consumer activity | 6 |
| 5861 | WMI-Activity | Permanent WMI event subscription | 6 |
| 400/4103 | PowerShell | PowerShell host initialization | 1 |

---

## Source Repository

- GitHub: https://github.com/OTRF/ThreatHunter-Playbook  
- Documentation: https://threathunterplaybook.com/  
- Security Datasets: https://securitydatasets.com/  
- All hunts in this catalog: `docs/hunts/windows/` directory, metadata in `metadata.yaml`, queries in `notebook.md`
