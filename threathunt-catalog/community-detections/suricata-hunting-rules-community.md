# Community Suricata Hunting Rules Catalog

Curated content from travisbgreen/hunting-rules and community Suricata hunting resources beyond the core ET/Pro ruleset. These are **behavioral** rules that detect suspicious tool usage and infrastructure interactions, not malware signatures.

---

## travisbgreen/hunting-rules — Technique Catalog

**Source:** https://github.com/travisbgreen/hunting-rules  
**Philosophy:** Detect the *presence of security tools and C2 infrastructure callbacks* — useful both offensively (attacker tools contacting infrastructure) and defensively (authorized red team callbacks).

### Pattern Categories

#### 1. Security Tool Infrastructure Callbacks (OAST / OOB Interaction)

These rules detect Out-of-Band (OOB) interaction service callbacks — used by both attackers (confirming code execution in targets) and bug bounty hunters:

```suricata
# Interactsh — open-source OAST platform widely used with nuclei scanner
alert dns any any -> any any (msg:"TGI HUNT Possible Interactsh DNS Interaction";
  content:"interactsh.com"; nocase; dns.query; classtype:trojan-activity; sid:2610001;)

alert tls any any -> any any (msg:"TGI HUNT Possible Interactsh TLS Interaction";
  content:"interactsh.com"; nocase; tls.sni; classtype:trojan-activity; sid:2610002;)

# Burp Collaborator — OAST used by Burp Suite Professional
alert dns any any -> any any (msg:"TGI HUNT Possible Burp Collaborator DNS Interaction";
  content:"burpcollaborator.net"; nocase; dns.query; classtype:trojan-activity; sid:2610010;)

# Canarytokens.com — honeypot callbacks
alert dns any any -> any any (msg:"TGI HUNT Possible Canarytoken DNS Interaction";
  content:"canarytokens.com"; nocase; dns.query; classtype:trojan-activity; sid:2610020;)

# dnslog.cn — Chinese OAST platform
alert dns any any -> any any (msg:"TGI HUNT Possible DNSLog DNS Interaction";
  content:"dnslog.cn"; nocase; dns.query; classtype:trojan-activity; sid:2610030;)
```

**Hunt value:** OAST callbacks in corporate DNS confirm successful SSRF, XXE, or code execution. Any of these in your DNS logs (especially from internal servers) warrants immediate investigation.

#### 2. Vulnerability Scanner Infrastructure

```suricata
# Nessus vulnerability scanner check-in domain
alert dns any any -> any any (msg:"TGI HUNT Possible Nessus Scanner DNS Query";
  content:"w.nessus.org"; nocase; dns.query; sid:2610100;)

# Edgescan scanner
alert dns any any -> any any (msg:"TGI HUNT Possible Edgescan Scanner DNS Query";
  content:"scannermcscanface-edgescan.com"; nocase; dns.query; sid:2610101;)

# BinaryEdge scanner
alert tls any any -> any any (msg:"TGI HUNT Possible BinaryEdge Scanner TLS";
  content:"binaryedge.io"; nocase; tls.sni; sid:2610110;)

# Censys scanner
alert tls any any -> any any (msg:"TGI HUNT Possible Censys Scanner TLS";
  content:"censys.io"; nocase; tls.sni; sid:2610111;)

# Kryptoslogic scanner (widely used by threat intel vendors)
alert tls any any -> any any (msg:"TGI HUNT Possible Kryptoslogic Scanner TLS";
  content:"kryptoslogic.com"; nocase; tls.sni; sid:2610112;)
```

#### 3. Penetration Testing Tool Callbacks

```suricata
# pwn.af — redirect/callback service
alert dns any any -> any any (msg:"TGI HUNT Possible pwn.af Pentest Callback";
  content:"pwn.af"; nocase; dns.query; sid:2610200;)

# LeakIX — vulnerability scanning service  
alert tls any any -> any any (msg:"TGI HUNT Possible LeakIX Scanner";
  content:"leakix.net"; nocase; tls.sni; sid:2610210;)

# webhook.site — free webhook receiver (used for exfil/callback testing)
alert tls any any -> any any (msg:"TGI HUNT Possible webhook.site Callback";
  content:"webhook.site"; nocase; tls.sni; sid:2610220;)

# requestbin — HTTP request inspection
alert tls any any -> any any (msg:"TGI HUNT Possible RequestBin Callback";
  content:"requestbin.com"; nocase; tls.sni; sid:2610221;)
```

---

## Key Suricata Hunting Rule Patterns

These are the core patterns to build custom hunting rules from:

### Pattern 1: Unusual Protocol on Standard Port

```suricata
# HTTP on port 443 (HTTPS port) without TLS — proxy bypass attempt
alert http any any -> any 443 (msg:"HUNT HTTP traffic on HTTPS port";
  flow:to_server,established;
  classtype:protocol-command-decode;
  sid:9000001;)

# TLS on non-standard port (C2 evasion)
alert tls any any -> any ![443,8443,993,995,465,636,989,990,5061,8883] 
  (msg:"HUNT TLS on non-standard port";
  flow:to_server,established;
  tls.store;
  sid:9000002;)
```

### Pattern 2: Suspicious DNS

```suricata
# Long DNS query (tunneling indicator)
alert dns any any -> any any (msg:"HUNT Long DNS query > 100 chars";
  dns.query; content:"."; pcre:"/^.{100,}\./";
  sid:9000010;)

# DNS query with high entropy label (DGA indicator)
alert dns any any -> any any (msg:"HUNT DNS query with very long label";
  dns.query; pcre:"/[a-z0-9]{40,}\./";
  sid:9000011;)

# DNS TXT response (tunneling exfil)
alert dns any any -> any any (msg:"HUNT DNS TXT response";
  dns.query; dns.answer; byte_test:1,>,64,0,relative;
  sid:9000012;)
```

### Pattern 3: User-Agent Hunting

```suricata
# Empty user-agent (automated tool)
alert http any any -> any any (msg:"HUNT Empty User-Agent";
  flow:to_server,established;
  http.user_agent; content:"";
  sid:9000020;)

# curl default user-agent (common in malware)
alert http any any -> any any (msg:"HUNT curl User-Agent";
  flow:to_server,established;
  http.user_agent; content:"curl/"; startswith;
  sid:9000021;)

# Python requests (common in malware/implants)
alert http any any -> any any (msg:"HUNT Python-requests User-Agent";
  flow:to_server,established;
  http.user_agent; content:"python-requests/";
  sid:9000022;)

# Go HTTP client (Sliver, many Go-based implants)
alert http any any -> any any (msg:"HUNT Go-http-client User-Agent";
  flow:to_server,established;
  http.user_agent; content:"Go-http-client/";
  sid:9000023;)

# Cobalt Strike default UA patterns
alert http any any -> any any (msg:"HUNT Cobalt Strike Default User-Agent";
  flow:to_server,established;
  http.user_agent; content:"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727)";
  classtype:trojan-activity; sid:9000024;)
```

### Pattern 4: TLS Fingerprinting (Suricata JA3)

```suricata
# Cobalt Strike default JA3 (when not using malleable C2)
alert tls any any -> any any (msg:"HUNT Cobalt Strike JA3 Fingerprint";
  ja3.hash; content:"a0e9f5d64349fb13191bc781f81f42e1";
  classtype:trojan-activity; sid:9000030;)

# Known-bad JA3 list check
alert tls any any -> any any (msg:"HUNT TLS with known-malicious JA3";
  ja3.hash; content:"72a589da586844d7f0818ce684948eea";
  classtype:trojan-activity; sid:9000031;)

# Self-signed TLS cert (no CA chain)
alert tls any any -> any any (msg:"HUNT TLS Self-Signed Certificate";
  flow:established;
  tls.cert_issuer; tls.cert_subject; 
  pcre:"/self.signed|Self.Signed/i";
  sid:9000032;)
```

### Pattern 5: Beaconing Behavior (Threshold Rules)

```suricata
# Threshold-based beaconing detection — same host:port > 20 times/hour
alert http any any -> $EXTERNAL_NET any (msg:"HUNT Potential HTTP C2 Beaconing";
  flow:to_server,established;
  threshold:type threshold, track by_src, count 20, seconds 3600;
  classtype:policy-violation; sid:9000040;)

# DNS beaconing — same query repeated
alert dns any any -> any any (msg:"HUNT Repeated Identical DNS Query";
  threshold:type both, track by_src, count 15, seconds 300;
  dns.query; pcre:"/[a-z0-9\-]{5,20}\.[a-z]{2,6}$/";
  sid:9000041;)
```

### Pattern 6: Admin Protocol from Unexpected Sources

```suricata
# SMB from internet (always suspicious)
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"HUNT SMB from Internet";
  flow:to_server,established;
  classtype:policy-violation; sid:9000050;)

# RDP from internet
alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 (msg:"HUNT RDP from Internet";
  flow:to_server,established;
  classtype:policy-violation; sid:9000051;)

# WinRM from internet
alert tcp $EXTERNAL_NET any -> $HOME_NET [5985,5986] (msg:"HUNT WinRM from Internet";
  flow:to_server,established;
  classtype:policy-violation; sid:9000052;)
```

### Pattern 7: Data Exfiltration Indicators

```suricata
# Large HTTP POST to external
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HUNT Large HTTP POST Exfil Candidate";
  flow:to_server,established;
  http.method; content:"POST";
  http.request_body; byte_jump:0,0; byte_test:4,>,10485760,0;
  threshold:type limit, track by_src, count 1, seconds 60;
  classtype:policy-violation; sid:9000060;)

# FTP to external (data transfer)
alert ftp $HOME_NET any -> $EXTERNAL_NET any (msg:"HUNT FTP to External";
  flow:to_server,established;
  ftp.command; content:"STOR";
  sid:9000061;)
```

---

## Deploying Custom Hunting Rules

### Rule Management

```bash
# Add custom hunting rules to Suricata
mkdir -p /etc/suricata/rules/hunting
# Place your .rules files in /etc/suricata/rules/hunting/

# Add to suricata.yaml
cat >> /etc/suricata/suricata.yaml << 'EOF'
rule-files:
  - hunting/custom-hunting.rules
  - hunting/oast-detection.rules
EOF

# Reload rules without restart
kill -USR2 $(pidof suricata)
```

### Tracking Custom SIDs

Use SID ranges that don't conflict with ET Open (1-2999999) or community rules:
- `2610000–2619999` — travisbgreen/hunting-rules range
- `9000000–9099999` — safe range for local custom hunting rules

### Threshold Tuning

```yaml
# threshold.conf — tune per environment
threshold gen_id 1, sig_id 9000040, type limit, track by_src, count 1, seconds 300
suppress gen_id 1, sig_id 9000020, track by_src, ip 10.0.0.100  # suppress known scanner
```

---

## Quick Reference: Which Ruleset for Which Hunt

| Hunt Goal | Recommended Ruleset | Key Rules |
|-----------|--------------------|-----------| 
| Catch C2 beacons by known tool | ET Open/Pro | CS, Sliver, Havoc, Mythic signatures |
| Catch OAST callbacks (exec confirmation) | travisbgreen/hunting-rules | interactsh, Burp Collaborator |
| Detect scanner activity | travisbgreen/hunting-rules | Censys, BinaryEdge, Nessus |
| Detect lateral movement | Stamus Open LM Ruleset | LM-specific SMB/RDP/WMI patterns |
| Detect botnet C2 IPs | Abuse.ch Feodo Tracker | IP reputation rules |
| Detect malware TLS certs | Abuse.ch SSLBL | Known-malicious cert blacklist |
| Hunt protocol anomalies | Custom (pattern 1) | Non-standard port usage |
| Hunt beaconing behavior | Custom (pattern 5) | Threshold-based repetition |
