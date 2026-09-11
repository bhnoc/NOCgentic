# PCAP Analysis Skills

## Tools Reference

| Tool | Type | Primary Use | Notes |
|------|------|-------------|-------|
| **Wireshark** | GUI | Interactive protocol decode, display filters, stream follow | Best for manual investigation |
| **tshark** | CLI | Scriptable field extraction, batch analysis | Wireshark engine, pipeable to grep/awk/sort |
| **tcpdump** | CLI | Capture + BPF filtering, lightweight live capture | Standard on all Unix systems |
| **Arkime** (Moloch) | Platform | Large-scale PCAP indexing and search; 10+ Gbps scale | Full-text search across sessions |
| **NetworkMiner** | GUI | File/artifact extraction from PCAP | Extracts files, images, emails, passwords passively |
| **Brim** (Zed Lake) | Desktop | PCAP + Zeek log analysis with ZQL queries | Automatically runs Zeek on loaded PCAP |
| **tcpflow** | CLI | TCP stream reassembly and file carving | Better than tshark for stream reconstruction |
| **pcapfex** | CLI | Packet Capture Forensic Evidence eXtractor | Carves files from PCAP |
| **FileTSAR** | Tool | File extraction and analysis workflow | Law enforcement origin, file-centric |
| **Stenographer** | Tool | Full-packet-capture with BPF-filtered retrieval | From Google; efficient storage |
| **Zeek** | Platform | Convert PCAP → structured logs (`zeek -r file.pcap`) | Best conversion workflow |
| **Suricata** | Platform | Apply IDS rules to PCAP offline (`suricata -r file.pcap`) | Retrospective rule application |
| **Scapy** | Python lib | Custom packet crafting, parsing, PCAP manipulation | Custom protocol dissection |
| **pyshark** | Python lib | Python wrapper around tshark for PCAP parsing | Scriptable deep packet inspection |
| **VAST** | Platform | Network telemetry engine with PCAP ingestion and query | High-performance analytics |
| **Xplico** | Tool | PCAP decode: extract email, HTTP, SIP, FTP, TFTP | Network forensics reconstruction |
| **YaraPCAP** | Tool | Apply YARA rules to files extracted from HTTP streams in PCAP | Malware file detection from PCAP |
| **ngrep** | CLI | grep-like pattern matching on PCAP content | Quick content searches in captures |
| **chaosreader** | CLI | Reconstruct sessions from PCAP into HTML/files | Human-readable session reconstruction |
| **dsniff** | CLI | Credential sniffing from PCAP (for analysis) | Password extraction from cleartext protocols |

## Analysis Techniques

### 1. Protocol Decode
- Apply full OSI-layer decode to identify protocol misuse, non-standard ports, and tunneling
- Use Wireshark's "Decode As" to force protocol interpretation on non-standard ports
- Check `Analyze > Expert Information` for warnings/errors indicating protocol anomalies

### 2. BPF Filter Construction (Capture Filters)
```bash
# Common BPF filters for tcpdump / tshark -f
tcpdump -r cap.pcap 'tcp port 80'                          # HTTP traffic
tcpdump -r cap.pcap 'host 192.168.1.100'                   # Traffic to/from specific host
tcpdump -r cap.pcap 'net 10.0.0.0/8'                       # Entire subnet
tcpdump -r cap.pcap 'not port 22 and not port 443'         # Exclude SSH and HTTPS
tcpdump -r cap.pcap 'tcp[tcpflags] & tcp-syn != 0'         # SYN packets only
tcpdump -r cap.pcap 'greater 1000'                         # Packets > 1000 bytes
tcpdump -r cap.pcap 'portrange 1024-65535'                 # High port traffic
```

### 3. Display Filter Construction (Wireshark/tshark -Y)
```bash
# HTTP hunting
tshark -r cap.pcap -Y 'http.request.method == "POST"'
tshark -r cap.pcap -Y 'http.response.code >= 400'
tshark -r cap.pcap -Y 'http.user_agent contains "python"'

# DNS hunting
tshark -r cap.pcap -Y 'dns.flags.rcode == 3'              # NXDOMAIN
tshark -r cap.pcap -Y 'dns.qry.type == 16'                # TXT queries
tshark -r cap.pcap -Y 'dns.qry.name matches "[a-z0-9]{25,}"' # Long domains

# TLS hunting
tshark -r cap.pcap -Y 'ssl.alert_message'                  # TLS alerts
tshark -r cap.pcap -Y 'tls.handshake.type == 1'            # ClientHello only

# TCP flags
tshark -r cap.pcap -Y 'tcp.flags.syn == 1 and tcp.flags.ack == 0'  # SYN scan
tshark -r cap.pcap -Y 'tcp.analysis.retransmission'        # Retransmissions
```

### 4. tshark Field Extraction Reference

```bash
# Extract src/dst IPs and ports
tshark -r cap.pcap -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport

# HTTP full request analysis
tshark -r cap.pcap -T fields -e ip.src -e http.host -e http.request.uri \
  -e http.user_agent -e http.request.method -Y 'http.request'

# DNS query/response extraction
tshark -r cap.pcap -T fields -e frame.time -e ip.src -e dns.qry.name \
  -e dns.resp.addr -e dns.flags.rcode -Y dns

# TLS SNI and JA3
tshark -r cap.pcap -T fields -e ip.dst -e tls.handshake.extensions_server_name \
  -e tls.handshake.ja3 -Y 'tls.handshake.type == 1'

# File extraction metadata
tshark -r cap.pcap -T fields -e ip.src -e ip.dst -e http.response.code \
  -e http.content_type -e http.file_data -Y 'http.response'

# Top talkers (pipe to sort)
tshark -r cap.pcap -T fields -e ip.src | sort | uniq -c | sort -rn | head -20

# Export HTTP objects to folder
tshark -r cap.pcap --export-objects http,/tmp/http_files/

# SMTP extraction
tshark -r cap.pcap -T fields -e smtp.req.command -e smtp.req.parameter -Y smtp

# Conversation statistics
tshark -r cap.pcap -z conv,tcp -q
tshark -r cap.pcap -z conv,ip -q

# Protocol hierarchy
tshark -r cap.pcap -z io,phs -q
```

### 5. Stream Reassembly

```bash
# Follow TCP stream in tshark
tshark -r cap.pcap -z follow,tcp,ascii,<stream_number> -q

# Extract all TCP streams as files
tcpflow -r cap.pcap -o /tmp/streams/

# NetworkMiner (GUI) — drag PCAP, click "Files" tab for extracted content
```

### 6. File Carving from PCAP

```bash
# Export all HTTP files
tshark -r cap.pcap --export-objects http,/tmp/carved/

# Export SMB files
tshark -r cap.pcap --export-objects smb,/tmp/carved_smb/

# tcpflow for all streams
tcpflow -r cap.pcap -o /tmp/flows/

# Apply YARA to carved files
yara -r /path/to/rules.yar /tmp/carved/

# YaraPCAP — YARA directly on HTTP streams in PCAP
python yarapcap.py -p cap.pcap -r malware.yar

# Check file hashes against threat intel
md5sum /tmp/carved/* | cut -d' ' -f1 | while read h; do
  curl -s "https://www.virustotal.com/api/v3/files/$h" \
    -H "x-apikey: $VT_API_KEY" | jq '.data.attributes.last_analysis_stats'
done
```

### 7. SSL/TLS Decryption

```bash
# Prerequisite: capture SSLKEYLOGFILE from client during session
# Set environment variable before starting browser:
SSLKEYLOGFILE=/tmp/ssl_keys.log firefox &

# In Wireshark: Edit > Preferences > Protocols > TLS > (Pre)-Master-Secret log filename

# In tshark:
tshark -r cap.pcap -o 'tls.keylog_file:/tmp/ssl_keys.log' -Y http -T fields \
  -e http.host -e http.request.uri -e http.user_agent
```

### 8. Convert PCAP to Zeek Logs

```bash
# Generate all Zeek logs from PCAP
zeek -r capture.pcap

# With specific scripts
zeek -r capture.pcap local

# With custom script
zeek -r capture.pcap /path/to/custom_detection.zeek

# Batch process multiple PCAPs
for f in *.pcap; do
  mkdir -p "zeek_${f%.pcap}"
  cd "zeek_${f%.pcap}"
  zeek -r "../$f"
  cd ..
done
```

### 9. Replay PCAP Through Suricata

```bash
# Apply Suricata rules to PCAP file
suricata -r capture.pcap -c /etc/suricata/suricata.yaml -l /tmp/suricata_output/

# With specific ruleset
suricata -r capture.pcap --set rule-files.0=/etc/suricata/et-hunting.rules
```

### 10. NetFlow Analysis from PCAP

```bash
# Generate NetFlow from PCAP with nfdump
softflowd -r capture.pcap -n 127.0.0.1:9996 -v 9
nfcapd -b 127.0.0.1 -p 9996 -l /tmp/nfcapd/ &
nfdump -r /tmp/nfcapd/nfcapd.* -s ip/bytes | head -20  # Top talkers by bytes
```

### 11. Custom Protocol Analysis with Scapy

```python
from scapy.all import *

# Load PCAP
pkts = rdpcap('capture.pcap')

# Filter by protocol
http_pkts = [p for p in pkts if p.haslayer(TCP) and p[TCP].dport == 80]

# Extract payload from all TCP packets
for p in pkts:
    if p.haslayer(Raw):
        payload = p[Raw].load
        if b'POST' in payload or b'GET' in payload:
            print(payload[:200])

# Find packets with specific byte pattern
suspicious = [p for p in pkts if p.haslayer(Raw) and b'\x4d\x5a' in p[Raw].load]  # MZ header
```

### 12. PCAP Forensic Workflow (End-to-End)

```
1. ACQUIRE      tcpdump/Wireshark live capture OR retrieve from Arkime/Stenographer
2. VALIDATE     Verify capture integrity; note time range, interface, capture filter
3. OVERVIEW     Protocol hierarchy (tshark -z io,phs), top talkers, conversation stats
4. CONVERT      zeek -r capture.pcap (get structured logs for hunting)
5. HUNT         Apply playbooks (beaconing, DGA, lateral movement, etc.) against Zeek logs
6. PIVOT        Identified suspicious sessions → filter PCAP by stream/IP for deep inspection
7. EXTRACT      Carve files; apply YARA; check hashes; extract credentials/artifacts
8. DECRYPT      If keys available, decrypt TLS sessions; re-analyze
9. TIMELINE     Correlate PCAP timestamps with endpoint and SIEM events
10. DOCUMENT    Record findings, preserve evidence, write hunt report
```

## Resources

- [tshark Tutorial and Filter Examples (hackertarget.com)](https://hackertarget.com/tshark-tutorial-and-filter-examples/)
- [Threat Hunting with Tshark (hackforlab.com)](https://hackforlab.com/threat-hunting-with-tshark/)
- [PCAP Analysis with Wireshark and Tshark (amirootyet.com)](https://www.amirootyet.com/post/pcap-analysis-with-wireshark-tshark/)
- [SANS FOR572 — Advanced Network Forensics](https://www.sans.org/cyber-security-courses/advanced-network-forensics-threat-hunting-incident-response)
- [Network Forensics PCAP Analysis Guide (decryptiondigest.com)](https://www.decryptiondigest.com/blog/network-forensics-pcap-analysis-wireshark-incident-response)
- [HackTricks PCAP Inspection](https://hacktricks.wiki/en/generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/index.html)
- [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
- [Arkime](https://arkime.com/)
