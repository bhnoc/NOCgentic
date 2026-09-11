# PB-04: Data Exfiltration Detection

**ATT&CK**: T1048 (Exfiltration Over Alternative Protocol), T1041 (Exfiltration Over C2 Channel), T1567 (Exfiltration Over Web Service), T1020 (Automated Exfiltration)
**Data Sources**: Zeek conn.log, files.log, http.log, dns.log, Suricata flow/fileinfo events, NetFlow
**Tools**: Zeek, Suricata, tshark, Python

## Hypothesis

After collecting target data, an attacker is moving it out of the network either in bulk (large file transfers) or slowly over time (low-and-slow), possibly using cloud storage, DNS tunneling, or encrypted C2 channels.

## Detection Method 1: Volume Anomaly in conn.log

```bash
# Top outbound byte transfers to external IPs
zeek-cut id.orig_h id.resp_h id.resp_p orig_bytes resp_bytes proto < conn.log | \
  awk -F'\t' '
    # Exclude internal→internal
    ($2 !~ /^10\.|^172\.|^192\.168\./) && $4+0 > 10000000 {
        print $4, $1, $2, $3
    }
  ' | sort -rn | head -20

# High outbound-to-inbound ratio (typical of exfiltration: send a lot, receive little)
zeek-cut id.orig_h id.resp_h orig_bytes resp_bytes < conn.log | \
  awk -F'\t' '
    ($3+0 > 1000000) && ($4+0 > 0) {
        ratio = $3/$4
        if (ratio > 50) print ratio, $1, $2, $3, $4
    }
  ' | sort -rn | head -20
```

## Detection Method 2: Files Log — Large Outbound File Transfers

```bash
# Flag large files transferred to external destinations
zeek-cut ts fuid id.orig_h id.resp_h filename mime_type total_bytes < files.log | \
  awk -F'\t' '
    ($2 !~ /^10\.|^172\.|^192\.168\./) && $7+0 > 5242880 {  # > 5MB
        print $7, $1, $3, $4, $5, $6
    }
  ' | sort -rn | head -20

# Flag archive files (ZIP, RAR, 7z, tar.gz) going outbound
zeek-cut id.orig_h id.resp_h filename mime_type < files.log | \
  awk -F'\t' '$4 ~ /zip|rar|x-7z|gzip|x-tar/' | \
  awk -F'\t' '$2 !~ /^10\.|^172\.|^192\.168\./' | sort | uniq -c | sort -rn
```

## Detection Method 3: Cloud Storage Destinations

```bash
# Flag uploads to known cloud storage services
CLOUD_DOMAINS="mega\.nz|drive\.google|dropbox\.com|onedrive\.live|box\.com|s3\.amazonaws|transfer\.sh|paste\.ee|pastebin\.com|file\.io|wetransfer"

zeek-cut ts id.orig_h host uri method < http.log | \
  awk -F'\t' -v pattern="$CLOUD_DOMAINS" '
    $3 ~ pattern && ($4 ~ /^\/upload|^\/file|PUT/) {
        print $1, $2, $3, $4, $5
    }
  ' | head -30

# Suricata eve.json
jq --arg pat "mega.nz|dropbox.com|drive.google|onedrive|box.com|s3.amazonaws|pastebin" \
  'select(.event_type=="http") | select(.http.hostname | test($pat))' eve.json
```

## Detection Method 4: HTTP POST with Large Bodies

```bash
# tshark: flag large HTTP POST requests
tshark -r cap.pcap -Y 'http.request.method == "POST" and http.content_length > 1000000' \
  -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri \
  -e http.content_length | sort | uniq -c | sort -rn

# Or in Zeek http.log
zeek-cut id.orig_h host uri method request_body_len < http.log | \
  awk -F'\t' '$4=="POST" && $5+0 > 100000' | sort -k5 -rn | head -20
```

## Detection Method 5: DNS-Based Exfiltration

See also: [PB-02: DNS Tunneling & DGA](./PB-02-dns-tunneling-dga.md)

```bash
# High DNS query volume from single host to single parent domain
zeek-cut id.orig_h query < dns.log | awk -F'\t' '
{
    n = split($2, parts, ".")
    if (n >= 2) {
        parent = parts[n-1]"."parts[n]
        count[$1"\t"parent]++
    }
}
END {
    for (k in count) if (count[k] > 200) print count[k], k
}' | sort -rn | head -20

# Flag unusually large DNS query strings
zeek-cut id.orig_h query < dns.log | awk -F'\t' 'length($2) > 100 {print length($2), $1, $2}' | sort -rn | head -20
```

## Detection Method 6: SMTP Exfiltration

```bash
# Zeek smtp.log: flag large email attachments or unusual recipients
zeek-cut ts id.orig_h from to last_reply < smtp.log | \
  awk -F'\t' '$5 !~ /^250/'  # Non-250 replies may indicate issues

# tshark: extract SMTP recipients and attachment size
tshark -r cap.pcap -Y smtp -T fields -e smtp.req.command -e smtp.req.parameter \
  | grep -E 'RCPT|DATA|MAIL FROM' | sort | uniq
```

## Detection Method 7: FTP Exfiltration

```bash
# Zeek ftp.log
zeek-cut ts id.orig_h id.resp_h user command arg file_size < ftp.log | \
  awk -F'\t' '$6=="STOR" && $7+0 > 1048576 {print}' | sort -k7 -rn

# tshark
tshark -r cap.pcap -Y ftp -T fields -e ip.src -e ip.dst -e ftp.request.command \
  -e ftp.request.arg | grep -E 'STOR|STOU|APPE'
```

## Detection Method 8: Time-Based Slow Exfiltration

```bash
# Detect low-and-slow exfiltration: small but consistent uploads over days
# Requires baseline: compare daily outbound bytes per dst against historical average

python3 << 'EOF'
import pandas as pd

df = pd.read_csv('conn.log', sep='\t', comment='#',
                 names=['ts','uid','orig_h','orig_p','resp_h','resp_p',
                        'proto','service','duration','orig_bytes','resp_bytes',
                        'conn_state','local_orig','local_resp','missed_bytes',
                        'history','orig_pkts','orig_ip_bytes','resp_pkts','resp_ip_bytes','tunnel_parents'])

df['ts'] = pd.to_numeric(df['ts'], errors='coerce')
df['date'] = pd.to_datetime(df['ts'], unit='s').dt.date
df['orig_bytes'] = pd.to_numeric(df['orig_bytes'], errors='coerce').fillna(0)

# Exclude internal traffic
external = df[~df['resp_h'].str.match(r'^(10\.|172\.|192\.168\.)')]

# Daily outbound bytes per src→dst pair
daily = external.groupby(['date', 'orig_h', 'resp_h'])['orig_bytes'].sum().reset_index()

# Flag consistent daily transfers (variance in bytes is low, mean is significant)
consistent = daily.groupby(['orig_h', 'resp_h'])['orig_bytes'].agg(['mean','std','count'])
slow_exfil = consistent[(consistent['count'] > 5) &
                        (consistent['mean'] > 100000) &
                        (consistent['std'] < consistent['mean'] * 0.3)]
print(slow_exfil.sort_values('mean', ascending=False).head(20))
EOF
```

## Behavioral Indicators

| Indicator | Exfil Type | Confidence |
|-----------|-----------|------------|
| Single session > 100MB outbound | Bulk | High |
| outbound:inbound byte ratio > 50:1 | Bulk | High |
| Upload to cloud storage (PUT/POST) | Web service | Medium |
| Archive files (ZIP/7z) to external | Bulk | Medium |
| DNS query length > 100 chars | DNS tunnel | High |
| Consistent daily outbound to same dst | Slow exfil | Medium |
| Large SMTP attachments to external | Email | Medium |
| Off-hours large transfers | Any | Medium |
| Encrypted upload to unknown IP | C2 channel | Low (needs corroboration) |

## Response

1. Capture full PCAP for implicated sessions and preserve as evidence
2. Identify what data was exfiltrated (reconstruct file contents from PCAP)
3. Notify data owners and legal/compliance (potential breach notification)
4. Block destination IP/domain at firewall
5. Review DLP logs for correlating alerts
6. Scope: check all hosts that communicated with the same dst over lookback period

## Sources

- [SANS FOR572](https://www.sans.org/cyber-security-courses/advanced-network-forensics-threat-hunting-incident-response)
- [Network Forensics Using PCAP Data](https://networkthreatdetection.com/network-forensics-using-pcap-data/)
- [SOC Investigation — Zeek Log Types](https://www.socinvestigation.com/threat-hunting-with-zeek-log-types-and-use-cases/)
