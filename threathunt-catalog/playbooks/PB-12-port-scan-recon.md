# PB-12: Port Scan & Network Reconnaissance Detection

**ATT&CK**: T1046 (Network Service Discovery), T1018 (Remote System Discovery), T1135 (Network Share Discovery)
**Data Sources**: Zeek conn.log, dns.log; Suricata flow events; PCAP
**Tools**: Zeek, tshark, Suricata

## Detection: Port Scan (Single Source → Many Ports)

```bash
# Zeek: Single IP scanning many unique ports in short window
zeek-cut ts id.orig_h id.resp_h id.resp_p conn_state < conn.log | \
  awk -F'\t' '
  {
    bucket = int($1/60)*60   # 1-minute buckets
    key = bucket"\t"$2"\t"$3
    ports[key][$4] = 1
    states[key][bucket"\t"$5] = 1
  }
  END {
    for (k in ports) {
      n = 0; for (p in ports[k]) n++
      if (n > 20) print n, k
    }
  }' | sort -rn | head -20

# tshark: Extract SYN scan (SYN without ACK = half-open scan)
tshark -r cap.pcap -Y 'tcp.flags == 0x002' -T fields \
  -e ip.src -e ip.dst -e tcp.dstport | sort | uniq -c | sort -rn | head -30
```

## Detection: Host Sweep (Single Source → Many Hosts)

```bash
# Single IP sweeping entire subnet
zeek-cut ts id.orig_h id.resp_h id.resp_p < conn.log | \
  awk -F'\t' '
  {
    bucket = int($1/300)*300   # 5-minute buckets
    key = bucket"\t"$2
    hosts[key][$3] = 1
  }
  END {
    for (k in hosts) {
      n = 0; for (h in hosts[k]) n++
      if (n > 30) print n, k
    }
  }' | sort -rn | head -10

# ICMP ping sweep
tshark -r cap.pcap -Y 'icmp.type == 8' -T fields \
  -e ip.src -e ip.dst | sort | uniq -c | sort -rn | head -20
```

## Detection: Service Discovery / Banner Grab

```bash
# Connections to common service ports from single src
zeek-cut id.orig_h id.resp_h id.resp_p conn_state < conn.log | \
  awk -F'\t' '$3 ~ /^(21|22|23|25|53|80|110|135|139|143|389|443|445|3389|8080|8443)$/' | \
  sort | uniq -c | sort -rn | head -20

# SSH version scanning (connect + immediate disconnect after banner)
zeek-cut ts id.orig_h id.resp_h duration < ssh.log | \
  awk -F'\t' '$4 < 2' | sort | uniq -c | sort -rn | head -10  # Very short SSH sessions
```

## Detection: SMB Enumeration / Share Discovery

```bash
# Net view / share enumeration via SMB
zeek-cut ts id.orig_h id.resp_h path < smb_mapping.log | \
  awk -F'\t' '$4 ~ /IPC\$/' | sort | uniq -c | sort -rn | head -20

# Multiple share access attempts = reconnaissance
zeek-cut id.orig_h id.resp_h path < smb_mapping.log | sort | uniq -c | sort -rn | head -20
```

## Detection: DNS Reconnaissance

```bash
# Zone transfer attempts (AXFR)
zeek-cut id.orig_h query qtype_name < dns.log | \
  awk -F'\t' '$3 == "AXFR"' | sort | uniq

# Reverse DNS sweeps (many PTR queries from same src)
zeek-cut ts id.orig_h qtype_name query < dns.log | \
  awk -F'\t' '
    $3 == "PTR" {
      bucket = int($1/300)*300
      key = bucket"\t"$2
      count[key]++
    }
    END { for (k in count) if (count[k] > 50) print count[k], k }
  ' | sort -rn | head -10

# AD-specific SRV queries (enumeration)
zeek-cut id.orig_h query qtype_name < dns.log | \
  awk -F'\t' '$3=="SRV" && $2 ~ /_ldap|_kerberos|_gc|_msdcs/' | sort | uniq -c
```

## Suricata Detection

```bash
# Enable ET rules for scanning:
# ET/SCAN category
grep -r "ET SCAN" /etc/suricata/rules/ | head -20

# Custom rule for port scan
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
  msg:"Possible Port Scan — Many Unique Ports";
  flags:S;
  threshold: type threshold, track by_src, count 30, seconds 30;
  sid:9003001; rev:1;)
```

## Tuning / False Positive Reduction

- Exclude vulnerability scanners and asset management tools (known IPs)
- Exclude monitoring systems (Nagios, Zabbix)
- Exclude IT admin subnet for service discovery workflows
- Set minimum threshold to 20+ unique ports/hosts to reduce noise

## Sources

- [MITRE ATT&CK T1046](https://attack.mitre.org/techniques/T1046/)
- [SOC Investigation — Zeek Log Types](https://www.socinvestigation.com/threat-hunting-with-zeek-log-types-and-use-cases/)
