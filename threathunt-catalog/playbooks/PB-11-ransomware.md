# PB-11: Ransomware Network Indicators & Detection

**ATT&CK**: T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery), T1021.002 (SMB), T1041 (C2 Exfiltration)
**Data Sources**: Zeek conn.log, smb_files.log, dns.log, files.log; Suricata smb/alert events; NetFlow
**Tools**: Zeek, Suricata (ET rules), tshark

## Overview

Modern ransomware operations follow a pattern: initial compromise → lateral movement → credential theft → data exfiltration → encryption. Network detection is possible at multiple stages before encryption begins.

---

## Stage 1: Initial Access (Network-Visible)

```bash
# Phishing delivery via email — SMTP attachment
zeek-cut ts id.orig_h id.resp_h from to mime_type < smtp.log | \
  awk -F'\t' '$6 ~ /application\/zip|application\/x-msdownload|application\/vnd.ms-excel/' | sort | uniq

# Drive-by download — HTTP
zeek-cut ts id.orig_h host uri mime_type status_code < http.log | \
  awk -F'\t' '$5 ~ /application\/x-dosexec|application\/zip/ && $6 == "200"' | sort | uniq

# Malicious ISO/IMG via HTTP (common 2022–2025 technique)
zeek-cut ts id.orig_h host uri mime_type < http.log | \
  awk -F'\t' '$5 ~ /iso|img|application\/octet-stream/' | \
  awk -F'\t' '$3 ~ /\.iso$|\.img$/'
```

---

## Stage 2: C2 Establishment

```bash
# Ransomware frequently calls home for encryption keys or operational check-in
# Hunt beaconing immediately after initial access (see PB-01)

# DNS queries to newly registered domains (age < 30 days)
# → Use urlscan.io or whois batch lookup for domain age

# Common ransomware C2 ports: 443, 80, 8443, 4444
# Hunt for HTTPS to IP (no SNI) right after initial access
zeek-cut ts id.orig_h id.resp_h id.resp_p server_name < ssl.log | \
  awk -F'\t' '($4==443 || $4==8443) && ($5 == "" || $5 == "-")' | \
  awk -F'\t' '$3 !~ /^10\.|^172\.|^192\.168\./' | sort | uniq
```

---

## Stage 3: Lateral Movement (SMB Sweep)

```bash
# Ransomware commonly sweeps the network via SMB to find additional targets
# Large-scale SMB connection sweep in short time window

zeek-cut ts id.orig_h id.resp_h id.resp_p conn_state < conn.log | \
  awk -F'\t' '
    $4==445 {
      bucket = int($1/60)*60  # 1-minute buckets
      key = bucket"\t"$2
      hosts[key][$3] = 1
    }
    END {
      for (k in hosts) {
        n = 0; for (h in hosts[k]) n++
        if (n > 10) print n, k
      }
    }
  ' | sort -rn | head -20

# Suricata rule for SMB sweep
alert tcp $HOME_NET any -> $HOME_NET 445 (
  msg:"Possible Ransomware SMB Sweep";
  flags:S;
  threshold: type threshold, track by_src, count 20, seconds 10;
  sid:9002001; rev:1;)
```

---

## Stage 4: Data Exfiltration (Pre-Encryption)

Modern ransomware exfiltrates data before encryption for double-extortion leverage.

```bash
# Large outbound transfers before encryption event
# (see PB-04 for full exfiltration detection)

# Hunt for staging to cloud storage
EXFIL_DESTINATIONS="mega\.nz|dropbox\.com|transfer\.sh|anonfiles\.com|gofile\.io|ufile\.io"
zeek-cut ts id.orig_h host uri method request_body_len < http.log | \
  awk -F'\t' -v pattern="$EXFIL_DESTINATIONS" '$3 ~ pattern && ($4=="POST" || $4=="PUT")' | sort

# Hunt for network shares being accessed (file staging for exfil)
zeek-cut ts id.orig_h id.resp_h action path < smb_files.log | \
  awk -F'\t' '$4 ~ /READ/' | sort -k1 | head -30
```

---

## Stage 5: Encryption Phase (SMB Mass Write)

This is the most distinctive ransomware network signature — mass file writes over SMB to network shares.

```bash
# Mass SMB write operations (file encryption in progress)
zeek-cut ts id.orig_h id.resp_h action name size < smb_files.log | \
  awk -F'\t' '
    $4 == "WRITE" || $4 == "SET_ATTR" {
      bucket = int($1/60)*60
      key = bucket"\t"$2"\t"$3
      writes[key]++
      total_bytes[key] += $6+0
    }
    END {
      for (k in writes) if (writes[k] > 50) 
        print writes[k], total_bytes[k], k
    }
  ' | sort -rn | head -20

# Renamed file extensions (ransomware adds extension to encrypted files)
# Watch for file names in smb_files.log changing to unknown extensions
zeek-cut id.orig_h name < smb_files.log | \
  awk -F'\t' '{
    n = split($2, parts, ".")
    if (n >= 2) {
      ext = parts[n]
      if (length(ext) >= 3 && length(ext) <= 8) exts[ext]++
    }
  } END {
    for (e in exts) if (exts[e] > 10) print exts[e], e
  }' | sort -rn | head -30
# Unknown extensions with high frequency = ransomware encryption

# Suricata: ET rule categories for ransomware
# - et/trojan (malware communication)
# - et/ransomware (dedicated category in ET Pro)
```

---

## Stage 6: Shadow Copy / Recovery Inhibition

```bash
# vssadmin delete shadows via network (WMI/RPC)
zeek-cut endpoint operation < dce_rpc.log | \
  grep -i "IWbem\|WMI" | sort | uniq

# Volume Shadow Copy service manipulation via SMB
# Also visible in Windows Event Logs 7036 (Service stopped) for VSS
```

---

## Ransomware-Specific Suricata Rules

```bash
# ET Open includes ransomware categories
# Key rules to enable:
# sid:2022573 - Cobalt Strike (ransomware initial compromise)
# ET/Trojan categories for known ransomware families:
# - LockBit (ET:LOCKBIT_*)
# - BlackCat/ALPHV
# - Cl0p
# - REvil/Sodinokibi
# - Conti (historic but patterns still appear)

# Check which ransomware rules are enabled
suricata-update list-enabled-sources | grep ransomware
grep -i "ransomware\|lockbit\|blackcat\|cl0p" /etc/suricata/rules/*.rules | head -20
```

---

## Ransomware Timeline Correlation

```
T-minus hours/days:
  □ Phishing email with ISO/ZIP delivered (smtp.log, files.log)
  □ Initial malware execution → first C2 connection (conn.log + ssl.log)

T-minus hours:
  □ Lateral movement via SMB/RDP (smb_mapping.log, rdp.log)
  □ Credential theft (kerberos.log anomalies, ntlm.log)
  □ Reconnaissance (dns.log - AD SRV queries, conn.log - port scan)

T-minus 30 min - few hours:
  □ Data staging + exfiltration to cloud (http.log, conn.log - large outbound)
  □ Shadow copy deletion (dce_rpc.log - WMI calls)

T=0 Encryption:
  □ Mass SMB WRITE operations (smb_files.log)
  □ Unknown file extensions appearing
  □ High SMB traffic burst
  □ C2 beacon stops (implant cleans up)
```

---

## Response

```
IMMEDIATE
  □ Isolate affected systems network segment
  □ Block outbound traffic to identified C2 IPs/domains
  □ Disable SMB between workstations at firewall
  □ Preserve PCAP evidence for forensics

SCOPE
  □ Identify all systems showing SMB write anomalies
  □ Review smb_files.log for encrypted file extensions across all hosts
  □ Check which network shares were accessed

RECOVERY
  □ Identify backup status (Volume Shadow Copies likely deleted)
  □ Restore from offline/air-gapped backups
  □ Don't pay ransom without legal/insurance guidance
```

## Sources

- [Suricata for Modern Network Defence (secpro.substack.com)](https://secpro.substack.com/p/243-suricata-in-modern-network-defence)
- [DFIR Report — Ransomware Case Studies](https://thedfirreport.com/)
- [Ransomware Lateral Movement Detection (Medium)](https://alican-kiraz1.medium.com/destroy-the-ransomware-threat-part-1-1-detection-and-prevention-6785aa7e1154)
- [ET Open Rules — Ransomware Category](https://rules.emergingthreats.net/)
