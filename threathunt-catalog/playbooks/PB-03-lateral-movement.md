# PB-03: Lateral Movement Detection

**ATT&CK**: T1021.001 (RDP), T1021.002 (SMB/PsExec), T1021.006 (WinRM), T1047 (WMI), T1569.002 (Remote Services), T1550.002 (Pass-the-Hash)
**Data Sources**: Zeek smb_mapping.log, smb_files.log, kerberos.log, ntlm.log, conn.log, rdp.log, ssh.log, Suricata smb/krb5 events
**Tools**: Zeek, Suricata, Stamus lateral movement ruleset

## Hypothesis

An attacker who has gained initial access is moving laterally through the network using standard Windows protocols (SMB, RDP, WMI, WinRM) to reach high-value targets like domain controllers, file servers, or jump hosts.

## Stage 1: Network Reconnaissance (Pre-Movement)

### Internal Port Scan / Host Discovery

```bash
# Zeek: single src IP touching many unique dst IPs in short window
zeek-cut ts id.orig_h id.resp_h id.resp_p < conn.log | awk -F'\t' '
{
    bucket = int($1/300)*300
    key = bucket"\t"$2
    hosts[key][$3] = 1
    ports[key][$3"_"$4] = 1
}
END {
    for (k in hosts) {
        n = 0; for (h in hosts[k]) n++
        if (n > 20) print n, k
    }
}' | sort -rn | head -20

# Flag SMB sweep on port 445
zeek-cut id.orig_h id.resp_h id.resp_p conn_state < conn.log | \
  awk -F'\t' '$3==445 {print $1, $2, $4}' | sort | uniq -c | sort -rn
```

### LDAP/AD Enumeration via DNS

```bash
# DNS queries for AD-specific SRV records — typical for reconnaissance
zeek-cut id.orig_h query qtype_name < dns.log | \
  awk -F'\t' '$3=="SRV" && $2 ~ /_ldap|_kerberos|_gc/' | sort | uniq -c | sort -rn
```

## Stage 2: SMB-Based Lateral Movement

### Admin Share Access Detection

```bash
# Zeek: flag access to administrative shares
zeek-cut ts id.orig_h id.resp_h path action < smb_mapping.log | \
  awk -F'\t' '$4 ~ /\\\\ADMIN\$|\\\\C\$|\\\\IPC\$/' | sort | uniq -c | sort -rn

# Suricata eve.json
jq 'select(.event_type=="smb") | select(.smb.tree | test("ADMIN\\$|C\\$|IPC\\$"))' eve.json
```

### PsExec Detection Pattern

PsExec creates a named pipe over IPC$, copies a service binary to ADMIN$, then starts the service:

```bash
# Step 1: IPC$ connection
zeek-cut ts id.orig_h id.resp_h path < smb_mapping.log | awk -F'\t' '$4 ~ /IPC\$/'

# Step 2: File copy to ADMIN$ (service binary)
zeek-cut ts id.orig_h id.resp_h path name action < smb_files.log | \
  awk -F'\t' '$4 ~ /ADMIN\$/ && $6 ~ /WRITE/'

# Step 3: Correlate both on same src→dst pair within short time window
```

### Workstation-to-Workstation SMB (Unusual)

```bash
# Flag workstation→workstation SMB connections
# Assumes workstations are in 10.0.10.0/24, servers in 10.0.20.0/24
zeek-cut id.orig_h id.resp_h id.resp_p < conn.log | \
  awk -F'\t' '$3==445 && $1 ~ /^10\.0\.10\./ && $2 ~ /^10\.0\.10\./' | \
  sort | uniq -c | sort -rn
```

## Stage 3: RDP-Based Lateral Movement

```bash
# Zeek: flag RDP connections from unexpected sources
zeek-cut ts id.orig_h id.resp_h < rdp.log | sort | uniq -c | sort -rn

# tshark: extract RDP sessions
tshark -r cap.pcap -Y 'tcp.dstport == 3389' -T fields \
  -e frame.time -e ip.src -e ip.dst -e tcp.flags | sort | uniq -c | sort -rn

# Flag RDP from workstation (not expected — should come from jump hosts)
zeek-cut id.orig_h id.resp_h < rdp.log | \
  awk -F'\t' '$1 ~ /^10\.0\.10\./' | sort | uniq
```

## Stage 4: WMI / WinRM Lateral Movement

```bash
# WMI uses port 135 (EPM) then dynamic high ports for DCOM
# Zeek dce_rpc.log captures WMI calls
zeek-cut ts id.orig_h id.resp_h endpoint operation < dce_rpc.log | \
  awk -F'\t' '$4 ~ /IWbem|WMI/' | sort | uniq

# WinRM on 5985 (HTTP) or 5986 (HTTPS)
zeek-cut id.orig_h id.resp_h id.resp_p < conn.log | \
  awk -F'\t' '$3==5985 || $3==5986' | sort | uniq -c | sort -rn
```

## Stage 5: Kerberos-Based Detection

```bash
# Kerberos TGT usage across multiple hosts (Golden Ticket indicator)
zeek-cut ts id.orig_h id.resp_h success client service < kerberos.log | \
  awk -F'\t' '$4=="true"' | sort -k3 | uniq -c | \
  awk '{if ($1 > 5) print}' | sort -rn | head -20

# Auth ticket without preceding new_ticket (Golden Ticket)
# Requires custom Zeek script tracking ticket issuance vs use

# AS-REP Roasting: AS-REQ without preauth
zeek-cut ts id.orig_h id.resp_h request_type client error_msg < kerberos.log | \
  awk -F'\t' '$4=="AS" && $6=="KDC_ERR_PREAUTH_REQUIRED"'
# Note: If we see AS-REQ for accounts without this error, preauth is disabled
```

## Stage 6: Pass-the-Hash / NTLM Detection

```bash
# Zeek NTLM log - flag pass-the-hash patterns (NTLM auth where Kerberos expected)
zeek-cut ts id.orig_h id.resp_h success username domain < ntlm.log | sort | uniq

# Flag NTLM from hosts that should use Kerberos (domain-joined in known subnet)
# Pass-the-Hash: NTLM Type3 with no preceding Type1/Type2 (replay)
```

## MITRE Technique → Network Observable Mapping

| Technique | Protocol | Port | Zeek Log | Key Indicator |
|-----------|---------|------|----------|---------------|
| T1021.001 RDP | RDP | 3389 | rdp.log | Unexpected src host |
| T1021.002 SMB/PsExec | SMB | 445 | smb_mapping.log | ADMIN$/C$ access |
| T1021.006 WinRM | WinRM | 5985/5986 | conn.log | Workstation src |
| T1047 WMI | DCE/RPC | 135+ | dce_rpc.log | IWbem endpoint |
| T1569.002 Remote Svc | SMB | 445 | smb_files.log | Service EXE copy to ADMIN$ |
| T1550.002 PtH | SMB/NTLM | 445 | ntlm.log | NTLM where Kerberos expected |
| T1550.003 PtT | Kerberos | 88 | kerberos.log | Ticket on unexpected host |

## Suricata Lateral Movement Ruleset

```bash
# Enable Stamus open lateral movement ruleset
suricata-update add-source stamus-lateral https://ti.stamus-networks.io/open/oisf-lateral.rules

# Key categories it covers:
# - Pass-the-Hash via SMB NTLM
# - PSExec service creation
# - WMI remote execution
# - Living-off-the-land techniques
```

## Response Playbook

```
STAGE 1 — CONTAIN
  □ Isolate affected source host(s) at network layer
  □ Block lateral movement paths (segment workstations from servers)
  □ Reset credentials of compromised accounts

STAGE 2 — SCOPE
  □ Map all hosts touched by lateral movement (dst IPs in smb_mapping/rdp logs)
  □ Check kerberos.log for ticket issuance chain to identify blast radius
  □ Review files.log for any staged malware dropped on dst hosts

STAGE 3 — ERADICATE
  □ Hunt persistence on each affected host (new services, scheduled tasks, registry)
  □ If Golden Ticket: rotate KRBTGT password twice (24 hours apart)
  □ Reset all admin credentials used during the movement period

STAGE 4 — DETECT
  □ Write detection rule for the specific lateral movement pattern observed
  □ Enable alerting on workstation-to-workstation SMB
  □ Enable alerting on unexpected RDP sources
```

## Sources

- [CyberDefenders — Lateral Movement Detection Guide](https://cyberdefenders.org/blog/soc-playbook-lateral-movement-detection-and-response-guide/)
- [Stamus — Open Lateral Movement Ruleset](https://www.stamus-networks.com/blog/threat-hunting-with-the-open-lateral-movement-ruleset-for-suricata)
- [Splunk — Active Directory Lateral Movement Detection](https://www.splunk.com/en_us/blog/security/active-directory-lateral-movement-detection-threat-research-release-november-2021.html)
