# BZAR — MITRE ATT&CK BZAR Zeek Analytics

**Source:** https://github.com/mitre-attack/bzar  
**What it is:** ATT&CK-mapped Zeek scripts that detect Windows lateral movement and execution techniques using DCE/RPC and SMB protocol analysis  
**Approach:** Pure network detection — no endpoint telemetry required  
**Key log:** `dce_rpc.log` (Zeek) — endpoint + operation fields identify the exact RPC call

BZAR is one of the most directly useful Zeek packages for network-based threat hunting. It maps DCE/RPC operations to MITRE ATT&CK techniques with real Zeek detection logic.

---

## Installation

```bash
zkg install bzar
# Or manual:
git clone https://github.com/mitre-attack/bzar
cp -r bzar/scripts /usr/share/zeek/site/bzar
echo "@load bzar" >> /usr/share/zeek/site/local.zeek
```

BZAR generates Zeek `notice.log` entries when technique-mapped patterns are observed.

---

## Detection Coverage by ATT&CK Technique

### Execution (TA0002)

| ATT&CK | Technique | DCE/RPC Endpoint | Operation | dce_rpc.log Pattern |
|--------|-----------|-----------------|-----------|---------------------|
| T1047 | WMI Remote Process | `IWbemServices` | `ExecMethod`, `ExecMethodAsync` | `endpoint=="IWbemServices" && operation in {"ExecMethod","ExecMethodAsync"}` |
| T1053.002 | Remote Scheduled Task (AT) | `atsvc` | `JobAdd` | `endpoint=="atsvc" && operation=="JobAdd"` |
| T1053.005 | Remote Scheduled Task (Schtask) | `ITaskSchedulerService` | `SchRpcRegisterTask`, `SchRpcRun` | `endpoint=="ITaskSchedulerService" && operation in {SchRpcRegisterTask,SchRpcRun}` |
| T1569.002 | Remote Service (PsExec-style) | `svcctl` | `CreateServiceA`, `CreateServiceW`, `StartServiceA`, `StartServiceW` | `endpoint=="svcctl" && operation in {CreateService*,StartService*}` |

### Persistence (TA0003)

| ATT&CK | Technique | DCE/RPC Endpoint | Operation | dce_rpc.log Pattern |
|--------|-----------|-----------------|-----------|---------------------|
| T1547.004 | WinLogon Helper (Print Provider) | `IRemoteWinspool` | `RpcAsyncInstallPrinterDriverFromPackage`, `RpcAsyncAddPrinterDriver` | Print spooler RPC pattern |
| T1546.003 | WMI Event Subscription | `IWbemServices` | `ExecMethod` targeting `ActiveScriptEventConsumer` | Compound — WMI + EventFilter binding |

### Lateral Movement (TA0008)

| ATT&CK | Technique | Protocol | Detection Pattern |
|--------|-----------|----------|-------------------|
| T1021.002 | SMB Admin Shares | SMB | `smb_files.log: path contains {ADMIN$, C$, IPC$} AND action in {SMB::FILE_OPEN, SMB::FILE_WRITE}` |
| T1021.003 | DCOM Lateral Movement | DCE/RPC | `endpoint=="IRemUnknown2"` with object UUID to known DCOM class IDs |

### Credential Access (TA0006)

| ATT&CK | Technique | DCE/RPC Endpoint | Operation | dce_rpc.log Pattern |
|--------|-----------|-----------------|-----------|---------------------|
| T1003.006 | DCSync | `drsuapi` | `DsGetNCChanges` | `endpoint=="drsuapi" && operation=="DsGetNCChanges" && id.orig_h != known_dc_ips` |
| T1557.001 | PetitPotam / NTLM Relay | `lsarpc` (over SMB) | `EfsRpcOpenFileRaw`, `NetrServerReq` | `endpoint in {"lsarpc","netlogon"} && operation in {"EfsRpcOpenFileRaw","NetrServerReqChallenge"}` |

---

## Direct Zeek dce_rpc.log Queries

### Hunt for All BZAR Execution Patterns

```bash
# Single query covering T1047, T1053, T1569
zeek-cut ts id.orig_h id.resp_h endpoint operation < dce_rpc.log | \
awk '
$5 == "IWbemServices" && ($6 == "ExecMethod" || $6 == "ExecMethodAsync") {
    print "T1047 WMI", $0
}
$5 == "atsvc" && $6 == "JobAdd" {
    print "T1053.002 AT", $0
}
$5 == "ITaskSchedulerService" && ($6 == "SchRpcRegisterTask" || $6 == "SchRpcRun") {
    print "T1053.005 Task", $0
}
$5 == "svcctl" && ($6 ~ /^CreateService/ || $6 ~ /^StartService/) {
    print "T1569.002 PsExec", $0
}'
```

### Hunt for DCSync (T1003.006) — Critical

```bash
# DCSync: drsuapi DsGetNCChanges from non-DC hosts
KNOWN_DCS="10.0.0.1 10.0.0.2"  # Update with your DC IPs
zeek-cut ts id.orig_h id.resp_h endpoint operation < dce_rpc.log | \
awk -v dcs="$KNOWN_DCS" '
BEGIN { split(dcs, dc_arr); for (i in dc_arr) known[dc_arr[i]]=1 }
$5 == "drsuapi" && $6 == "DsGetNCChanges" && !known[$2] {
    print "ALERT DCSync T1003.006:", $0
}'
```

### Hunt for PetitPotam (T1557.001)

```bash
zeek-cut ts id.orig_h id.resp_h endpoint operation < dce_rpc.log | \
awk '$5 == "lsarpc" && $6 == "EfsRpcOpenFileRaw" {
    print "ALERT PetitPotam T1557.001:", $0
}'
```

### Hunt for Remote Service Creation (T1569.002)

```bash
zeek-cut ts id.orig_h id.resp_h endpoint operation < dce_rpc.log | \
awk '$5 == "svcctl" && $6 ~ /^CreateService/ {
    print "ALERT RemoteService T1569.002:", $1, $2, "->", $3
}' | sort | uniq -c | sort -rn
```

---

## SMB-Based Detections (smb_files.log)

### Admin Share Access Pattern

```bash
# Hosts accessing ADMIN$ or C$ shares — lateral movement staging
zeek-cut ts id.orig_h id.resp_h path name action < smb_files.log | \
awk '$4 ~ /\\(ADMIN|C)\$/ {
    share[$2][$3]++
}
END {
    for (src in share)
        for (dst in share[src])
            if (share[src][dst] > 1)
                print src, "->", dst, "admin share access count:", share[src][dst]
}'
```

### PsExec Pattern (PSEXESVC.exe write to ADMIN$)

```bash
# PsExec drops PSEXESVC into ADMIN$ then executes via svcctl
zeek-cut ts id.orig_h id.resp_h path name action < smb_files.log | \
awk 'tolower($5) ~ /psexesvc/ && $4 ~ /ADMIN\$/ {
    print "ALERT PsExec T1569.002:", $0
}'
```

---

## BZAR Notice.log Output

When BZAR runs on live traffic, it writes to `notice.log` with these notice types:

| Notice Type | ATT&CK | Description |
|-------------|--------|-------------|
| `ATTACK::Lateral_Movement` | T1021 | Remote SMB admin share access + DCE/RPC execution |
| `ATTACK::Lateral_Movement_Doublepulsar` | — | DoublePulsar implant communication pattern |
| `ATTACK::Execution` | T1047, T1053, T1569 | DCE/RPC technique execution |
| `ATTACK::Persistence` | T1547.004 | Print spooler RPC persistence |
| `ATTACK::Collection` | T1039 | Remote SMB read from admin shares |

```bash
# Check BZAR alerts in notice.log
zeek-cut ts note id.orig_h id.resp_h msg < notice.log | \
awk '$2 ~ /^ATTACK::/ {print $0}' | sort -k2
```

---

## Combining BZAR with Suricata

BZAR operates at the protocol layer; Suricata catches the content. Use both:

```bash
# Cross-correlate BZAR alerts with Suricata ET alerts on same src/dst pair
# 1. Get BZAR attack pairs from notice.log
bzar_pairs=$(zeek-cut id.orig_h id.resp_h < notice.log | sort -u)

# 2. Check if Suricata also fired on same pairs  
jq -r 'select(.event_type=="alert") | [.src_ip, .dest_ip, .alert.signature] | @tsv' eve.json | \
while read src dst sig; do
    if echo "$bzar_pairs" | grep -q "^$src\t$dst$"; then
        echo "CORROBORATED: $src -> $dst | $sig"
    fi
done
```

---

## Key RPC UUIDs for Manual PCAP Analysis

When hunting in raw PCAP, these DCE/RPC interface UUIDs identify the protocol being used:

| UUID | Interface | Technique |
|------|-----------|-----------|
| `e3514235-4b06-11d1-ab04-00c04fc2dcd2` | DRSUAPI (DCSync) | T1003.006 |
| `367abb81-9844-35f1-ad32-98f038001003` | svcctl (remote service) | T1569.002 |
| `6bffd098-a112-3610-9833-46c3f87e345a` | atsvc (AT job) | T1053.002 |
| `f6beaff7-1e19-4fbb-9f8f-b89e2018337c` | ITaskSchedulerService | T1053.005 |
| `c84f01a3-1e59-4ed8-bc9b-d16da3349a80` | IWbemServices (WMI) | T1047 |
| `c681d488-d850-11d0-8c52-00c04fd90f7e` | EfsRpcOpenFileRaw (PetitPotam) | T1557.001 |

```bash
# Extract DCE/RPC UUIDs from PCAP using tshark
tshark -r capture.pcap -Y "dcerpc" -T fields \
  -e ip.src -e ip.dst -e dcerpc.cn_bind_if_id \
  | grep -E "e3514235|367abb81|6bffd098|f6beaff7|c84f01a3|c681d488"
```
