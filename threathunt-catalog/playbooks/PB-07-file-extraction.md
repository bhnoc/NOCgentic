# PB-07: File Extraction, YARA Scanning & Artifact Forensics

**ATT&CK**: T1105 (Ingress Tool Transfer), T1566 (Phishing), T1204 (User Execution)
**Data Sources**: Zeek files.log, http.log; Suricata fileinfo events, file-store; PCAP
**Tools**: NetworkMiner, tshark, tcpflow, Suricata file-store, YARA, Zeek file extraction

## Hypothesis

An attacker transferred malicious files over the network (malware dropper, payload, script) via HTTP, SMB, SMTP, FTP, or another protocol. These files can be carved from PCAP or extracted from NSM logs and analyzed.

---

## Method 1: Zeek File Extraction

```zeek
# zeek/local.zeek — enable file extraction
@load base/files/extract

redef FileExtract::prefix = "/tmp/zeek_files/";
redef FileExtract::default_limit = 10485760;  # 10MB limit

# Or selectively extract executables only
hook FileExtract::extract(f: fa_file, meta: fa_metadata, filename: string, limit: count) {
    if (f?$mime_type && f$mime_type == "application/x-dosexec")
        break;
}
```

```bash
# Run Zeek with file extraction enabled
mkdir -p /tmp/zeek_files
zeek -r capture.pcap /etc/zeek/site/local.zeek

# Files land in /tmp/zeek_files/
ls -lh /tmp/zeek_files/

# Cross-reference extracted files with files.log
zeek-cut ts fuid source mime_type filename md5 sha256 < files.log | sort
```

---

## Method 2: Suricata File Extraction

```yaml
# In suricata.yaml:
file-store:
  enabled: yes
  dir: /var/log/suricata/files
  force-hash: [md5, sha1, sha256]
  force-filestore: yes    # Store all files (not just rule matches)
  max-size: 10mb
  
# Or use rules to extract specific types:
```

```
# Suricata rule to extract PE files
alert http any any -> any any (msg:"HTTP EXE/DLL Download"; \
  filemagic:"PE32"; \
  filestore; sid:9001001; rev:1;)

alert http any any -> any any (msg:"HTTP ZIP Download"; \
  fileext:"zip"; \
  filestore; sid:9001002; rev:1;)
```

```bash
# Files appear in /var/log/suricata/files/
# Each file named by SHA256; metadata in eve.json fileinfo events

# Link file store to fileinfo metadata
jq 'select(.event_type=="fileinfo")' /var/log/suricata/eve.json | \
  jq '{sha256: .fileinfo.sha256, filename: .fileinfo.filename, 
       mime: .fileinfo.mimetype, src: .src_ip, dst: .dest_ip}'
```

---

## Method 3: tshark Object Export

```bash
# Export all HTTP transferred files
tshark -r capture.pcap --export-objects http,/tmp/http_extracted/

# Export SMB transferred files
tshark -r capture.pcap --export-objects smb,/tmp/smb_extracted/

# Export IMF (email) objects
tshark -r capture.pcap --export-objects imf,/tmp/email_extracted/

# Export DICOM, TFTP, and more
tshark -r capture.pcap --export-objects dicom,/tmp/dicom/
tshark -r capture.pcap --export-objects tftp,/tmp/tftp/

# List what was extracted
ls -lh /tmp/http_extracted/
```

---

## Method 4: NetworkMiner GUI Extraction

```
1. Open NetworkMiner
2. File > Open > select .pcap file
3. Click "Files" tab — all extracted files listed with:
   - Filename, size, source IP, destination IP, timestamp
   - MD5/SHA256 hash
4. Right-click → "Open folder" to access extracted files
5. "Parameters" tab shows URL parameters, POST data, credentials
6. "Credentials" tab shows cleartext passwords sniffed from protocols
7. "Messages" tab shows emails and chat messages
```

---

## Method 5: tcpflow Stream Extraction

```bash
# Reconstruct all TCP streams
tcpflow -r capture.pcap -o /tmp/streams/

# Result: one file per direction per TCP stream
ls /tmp/streams/
# e.g., 010.000.001.100.54321-001.002.003.004.00080 (src-dst)

# Search for file magic bytes in extracted streams
file /tmp/streams/* | grep -E 'PE32|PDF|Zip|7-zip|Microsoft'

# Extract specific stream range
tcpflow -r capture.pcap 'host 1.2.3.4 and port 80' -o /tmp/c2_stream/
```

---

## Method 6: YARA Rules Against Extracted Files

```bash
# Apply YARA rules to all extracted files
yara -r /path/to/yara-rules/ /tmp/http_extracted/ 2>/dev/null

# Common YARA rule repositories
# - https://github.com/Yara-Rules/rules
# - https://github.com/Neo23x0/signature-base (Florian Roth's signatures)
# - Elastic's detection rules (YARA for network extractions)

# Example YARA rule for detecting Cobalt Strike beacon
cat > /tmp/cobalt_strike.yar << 'EOF'
rule CobaltStrike_Beacon {
    meta:
        description = "Detects Cobalt Strike Beacon payload"
        author = "Threat Hunt Catalog"
    strings:
        $hdr = {4D 5A}                    // MZ header
        $s1 = "%s as %s\\%s: %d"         // CS beacon format string
        $s2 = "beacon.dll"
        $s3 = "ReflectiveLoader"
    condition:
        $hdr at 0 and (2 of ($s1, $s2, $s3))
}
EOF
yara /tmp/cobalt_strike.yar /tmp/http_extracted/
```

---

## Method 7: YaraPCAP — YARA Directly on PCAP HTTP Streams

```bash
# Install: pip install yarapcap
# Apply YARA rules to HTTP streams in PCAP without extracting files first

python yarapcap.py \
  --pcap capture.pcap \
  --rules /path/to/rules.yar \
  --write-matching-files /tmp/matches/ \
  --report /tmp/yarapcap_report.txt
```

---

## Method 8: Hash Lookup Against Threat Intelligence

```bash
# Extract hashes from Zeek files.log
zeek-cut md5 sha256 mime_type id.orig_h id.resp_h < files.log | \
  awk -F'\t' '$2 != "" && $2 != "-"' > /tmp/hashes_to_check.txt

# Batch VirusTotal lookup (requires API key)
while IFS=$'\t' read md5 sha256 mime src dst; do
  result=$(curl -s "https://www.virustotal.com/api/v3/files/$sha256" \
    -H "x-apikey: $VT_API_KEY" | \
    jq -r '"\(.data.attributes.last_analysis_stats.malicious)/\(.data.attributes.last_analysis_stats.total)"')
  echo "$result $sha256 $mime $src->$dst"
done < /tmp/hashes_to_check.txt | sort -rn | head -30

# MalwareBazaar lookup (free, no rate limit)
while IFS=$'\t' read md5 sha256 mime src dst; do
  curl -s -X POST "https://mb-api.abuse.ch/api/v1/" \
    -d "query=get_info&hash=$sha256" | jq '.data[0].signature'
done < /tmp/hashes_to_check.txt
```

---

## What to Look For in Extracted Files

| File Type | Suspicious Indicators |
|-----------|----------------------|
| **PE/EXE/DLL** | High import entropy, packed sections, ReflectiveLoader, known bad hash, CS/Meterpreter strings |
| **Office docs** | Macro streams, OLE objects, external template injection URLs, suspicious keywords |
| **PDF** | JavaScript, /Launch actions, embedded executables, /OpenAction with URI |
| **ZIP/RAR/7z** | Password-protected archives, executables inside, .lnk shortcuts |
| **PowerShell .ps1** | Base64-encoded commands, IEX/Invoke-Expression, download cradles |
| **Scripts (.vbs, .js, .bat)** | eval(), WScript.Shell, Base64, downloadstring, invoke-expression |
| **Linux ELF** | Stripped, upx packed, known miner or backdoor strings |

---

## Zeek files.log Key Fields

| Field | Description |
|-------|-------------|
| `ts` | Start timestamp |
| `fuid` | File unique ID (correlate with conn uid) |
| `tx_hosts` | Hosts that sent the file |
| `rx_hosts` | Hosts that received the file |
| `source` | Which analyzer detected the file (HTTP, SMTP, etc.) |
| `duration` | How long the transfer took |
| `local_orig` | Whether the sender is local |
| `is_orig` | Whether this is from the originator |
| `mime_type` | Detected MIME type |
| `filename` | Filename from protocol (if available) |
| `total_bytes` | Total file size |
| `md5` / `sha1` / `sha256` | File hashes (if extraction enabled) |

## Sources

- [NetworkMiner (Netresec)](https://www.netresec.com/?page=NetworkMiner)
- [Detecting Malicious Files with YARA as They Traverse the Network (Black Hat)](https://i.blackhat.com/USA-19/Wednesday/us-19-Bernal-Detecting-Malicious-Files-With-YARA-Rules-As-They-Traverse-the-Network-wp.pdf)
- [Stamus Networks — YARA File Analysis with Corelight](https://corelight.com/platform/yara-file-analysis)
- [SANS FOR572](https://www.sans.org/cyber-security-courses/advanced-network-forensics-threat-hunting-incident-response)
- [Suricata File Extraction Documentation](https://suricata.readthedocs.io/en/latest/file-extraction/file-extraction.html)
