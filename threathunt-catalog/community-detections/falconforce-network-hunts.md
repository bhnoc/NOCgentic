# FalconForceTeam FalconFriday — Network-Relevant Hunts

**Source:** https://github.com/FalconForceTeam/FalconFriday  
**Format:** KQL queries for Microsoft Defender for Endpoint (MDE) / Microsoft Sentinel  
**Focus:** Windows enterprise network attack paths; queries translate conceptually to Zeek/Suricata field equivalents

---

## Complete Network Hunt Catalog

| Hunt ID | Title | ATT&CK | Network Observable | MDE Table |
|---------|-------|---------|-------------------|-----------|
| 0xFF-0027 | Beacon Traffic via Common UAs to Limited Domains | T1071.001 | Host making periodic HTTPS requests using common browser UA strings but only to very small set of unique domains (beaconing) | DeviceNetworkEvents |
| 0xFF-0039 | Likely Lateral Movement with SharpRDP | T1021.001 | RDP session where clipboard activity is absent or process launch occurs immediately after connect (SharpRDP pattern) | DeviceNetworkEvents + DeviceProcessEvents |
| 0xFF-0582 | WinRM Plugin Lateral Movement | T1021.006 | WinRM connections (TCP/5985, TCP/5986) from workstations to workstations (vs. server-to-server) | DeviceNetworkEvents |
| 0xFF-0003 | LDAP Recon via Search Filters | T1018, T1069 | High-volume LDAP queries to DC (TCP/389) from non-admin workstations with unusual search filter patterns | DeviceNetworkEvents |
| 0xFF-0270 | NTLM Relay Attack | T1557.001 | Authentication to unexpected SMB target immediately following receipt of SMB connection — relay chain indicator | DeviceNetworkEvents |
| 0xFF-0060 | Azure AD Rare User-Agent App Sign-in | T1078.004 | Cloud auth from user-agent string seen < N times in tenant — C2 framework disguised as cloud app | CloudAppEvents |
| 0xFF-0061 | Azure AD UA/OS Mismatch | T1078.004 | Device's enrolled OS (Intune) differs from OS claimed in user-agent during sign-in | CloudAppEvents |
| 0xFF-0108 | Large Number of AD Objects Accessed | T1087 | Single user account performing LDAP binds that return > threshold unique objects in short window | DeviceNetworkEvents |
| 0xFF-0083 | Remote Process Invocation via SCM | T1543.003 | Service Control Manager traffic (TCP/445 → service install) immediately followed by process execution on target | DeviceNetworkEvents + DeviceProcessEvents |
| 0xFF-0485 | ADWS Connection from Unexpected Binary | T1069 | Active Directory Web Services (TCP/9389) connection initiated by non-standard process (not PowerShell/dcdiag) | DeviceNetworkEvents |

---

## Zeek/Suricata Analogs

These hunts target Windows network behaviors visible in Zeek/Suricata logs:

### 0xFF-0027 → C2 Beaconing (Zeek analog: PB-01)

```bash
# Hosts making many requests to tiny domain set (< 5 unique FQDNs) with common browser UAs
zeek-cut id.orig_h host user_agent < http.log \
  | awk '{count[$1" "$3]++; domains[$1][$2]=1}
         END {for (k in count) {
           split(k, a, " ")
           if (length(domains[a[1]]) < 5 && count[k] > 50)
             print k, count[k], length(domains[a[1]])
         }}'
```

### 0xFF-0039 → SharpRDP Detection (Zeek rdp.log)

```bash
# RDP connections — flag any from workstation IP ranges to other workstations
zeek-cut id.orig_h id.resp_h < rdp.log \
  | awk '$1 ~ /^192\.168\./ && $2 ~ /^192\.168\./ {print $0}'
```

### 0xFF-0582 → WinRM Lateral Movement (Zeek conn.log)

```bash
# WinRM from workstations (not servers)
zeek-cut id.orig_h id.resp_h id.resp_p service < conn.log \
  | awk '($3 == 5985 || $3 == 5986) && $1 ~ /^10\./ {print $0}'
```

### 0xFF-0270 → NTLM Relay (Zeek ntlm.log)

```bash
# NTLM auth on SMB — flag where username appears on multiple destination hosts within 5 min
zeek-cut ts id.orig_h id.resp_h username success < ntlm.log \
  | python3 -c "
import sys, collections
from datetime import datetime
events = []
for line in sys.stdin:
    parts = line.strip().split('\t')
    if len(parts) < 5: continue
    events.append({'ts': float(parts[0]), 'src': parts[1], 'dst': parts[2], 'user': parts[3]})
# Group by user, check if same user hits >1 dst within 300s
by_user = collections.defaultdict(list)
for e in events:
    by_user[e['user']].append(e)
for user, evts in by_user.items():
    evts.sort(key=lambda x: x['ts'])
    for i, e in enumerate(evts):
        window = [x for x in evts[i:] if x['ts'] - e['ts'] <= 300]
        if len(set(x['dst'] for x in window)) > 2:
            print(f'Possible NTLM relay: user={user} src={e[\"src\"]} {len(window)} auths in 5min')
            break
"
```

### 0xFF-0108 → LDAP Enumeration (Zeek conn.log)

```bash
# Workstations making many connections to DC port 389/636 (LDAP/LDAPS)
zeek-cut id.orig_h id.resp_h id.resp_p < conn.log \
  | awk '($3 == 389 || $3 == 636) {count[$1" "$2]++}
         END {for (k in count) if (count[k] > 50) print count[k], k}' \
  | sort -rn | head -20
```

---

## Translating MDE KQL → Zeek Field Mapping

| MDE Field | Zeek Equivalent | Notes |
|-----------|----------------|-------|
| `DeviceNetworkEvents.RemoteIP` | `conn.log: id.resp_h` | |
| `DeviceNetworkEvents.RemotePort` | `conn.log: id.resp_p` | |
| `DeviceNetworkEvents.LocalIP` | `conn.log: id.orig_h` | |
| `DeviceNetworkEvents.InitiatingProcessName` | No direct Zeek equivalent | Requires endpoint correlation |
| `DeviceNetworkEvents.ActionType == "ConnectionSuccess"` | `conn.log: conn_state IN {SF, S1, RSTO, RSTR}` | |
| `DeviceNetworkEvents.ActionType == "InboundConnectionAccepted"` | `conn.log: history contains "D"` | D = SYN received from responder |
| `CloudAppEvents.UserAgent` | `http.log: user_agent` | |
| `CloudAppEvents.Application` | `http.log: host` (partial) | |

---

## Key Behavioral Patterns (Tool-Agnostic)

All ten hunts above reduce to these network-observable behaviors. Hunt for these regardless of specific tool:

1. **Low domain diversity + high connection count** → C2 beaconing (PB-01)
2. **Workstation → workstation on admin protocols** → lateral movement (PB-03): RDP, WinRM, SMB, SCM
3. **Mass LDAP to DC from non-admin hosts** → AD enumeration (PB-12)
4. **NTLM auth to unexpected target immediately after receiving connection** → NTLM relay (PB-05)
5. **Cloud auth with novel user-agent** → credential theft / token replay (PB-05)
