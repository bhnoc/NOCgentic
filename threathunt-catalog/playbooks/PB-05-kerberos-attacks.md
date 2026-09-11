# PB-05: Kerberos Attack Detection

**ATT&CK**: T1558.001 (Golden Ticket), T1558.002 (Silver Ticket), T1558.003 (Kerberoasting), T1558.004 (AS-REP Roasting), T1550.003 (Pass-the-Ticket)
**Data Sources**: Zeek kerberos.log, ntlm.log, conn.log, Suricata krb5 events, PCAP
**Tools**: Zeek, Suricata, tshark, Wireshark

## Background

Kerberos authentication is the default in Active Directory environments. All ticket exchanges are visible at the network layer without decryption. Zeek's kerberos.log and Suricata's krb5 events provide rich visibility into these exchanges.

### Kerberos Flow (Normal)

```
Client → KDC (AS-REQ with pre-auth)
KDC → Client (AS-REP with TGT)
Client → KDC (TGS-REQ with TGT, requesting service ticket)
KDC → Client (TGS-REP with service ticket/ST)
Client → Service (AP-REQ with service ticket)
```

---

## Attack 1: Kerberoasting (T1558.003)

An attacker with any valid domain account requests service tickets (TGS) for service accounts using the weaker RC4 encryption type (etype 23), then cracks the encrypted ticket offline.

### Detection

```bash
# Zeek: flag TGS-REQ using RC4 (etype 23) for service accounts
zeek-cut ts id.orig_h id.resp_h success client service cipher error_msg < kerberos.log | \
  awk -F'\t' '$4=="true" && $7=="rc4-hmac" && $5~/\$/ == 0' | sort | uniq

# Multiple service TGS requests using RC4 from same src = Kerberoasting
zeek-cut id.orig_h cipher service < kerberos.log | \
  awk -F'\t' '$2=="rc4-hmac"' | sort | uniq -c | sort -rn | head -20

# Suricata krb5 events
jq 'select(.event_type=="krb5") | select(.krb5.encryption_type | test("rc4|23"))' eve.json
```

### Behavioral Profile
- Single src IP requesting TGS for multiple service accounts
- All requests use RC4 (etype 23) even when AES (17/18) is available
- Typically done in a short burst (all requests within minutes)
- Service accounts targeted (SPNs registered in AD)

---

## Attack 2: AS-REP Roasting (T1558.004)

Accounts with "Do not require Kerberos preauthentication" set can be targeted — the attacker requests a TGT without valid credentials, receives an encrypted response, and cracks it offline.

### Detection

```bash
# Zeek: AS-REQ responses where pre-auth was not required
# Normal: client sends PA-DATA (pre-auth data), KDC validates
# Roastable: AS-REQ without PA-DATA succeeds → KDC returns TGT encrypted with account password hash

zeek-cut ts id.orig_h client < kerberos.log | head -30
# Look for multiple AS-REQ from same src for different accounts in short window

# The giveaway: successful AS-REP (returning TGT) for account that should require preauth
zeek-cut ts id.orig_h success client < kerberos.log | \
  awk -F'\t' '$3=="true"' | sort -k4 | uniq -c | sort -rn

# Multiple unique accounts with successful AS-REP from one src = AS-REP Roasting
zeek-cut id.orig_h client < kerberos.log | sort | uniq | \
  awk -F'\t' '{count[$1]++; accounts[$1]=accounts[$1]" "$2} END {
    for (ip in count) if (count[ip] > 5) print count[ip], ip, accounts[ip]
  }' | sort -rn | head -10
```

---

## Attack 3: Golden Ticket (T1558.001)

An attacker with access to the KRBTGT account hash (obtained via DCSync or domain compromise) can forge a Ticket Granting Ticket (TGT) for any identity, with any group memberships, valid for arbitrary time.

### Detection

```bash
# Key indicator: TGT used in TGS-REQ that was NOT issued by the KDC in observable traffic
# Requires tracking ticket issuance (AS-REP) vs ticket usage (TGS-REQ)

# Zeek: flag anomalously long ticket lifetimes
# Normal Kerberos TGT validity: 10 hours
# Golden Tickets: often set to 10+ years

# Check for auth_ticket entries without preceding new_ticket for same client
# (Zeek kerberos.log has request_type field: AS, TGS)

zeek-cut ts id.orig_h id.resp_h request_type client < kerberos.log | \
  awk -F'\t' '{
    if ($4 == "AS") issued[$5] = 1
    if ($4 == "TGS" && !($5 in issued)) print "SUSPICIOUS TGS without AS-REP:", $0
  }'

# Wireshark: Kerberos TGT Lifetime field
# Filter: kerberos.endtime - kerberos.starttime > (10 * 3600) for Golden Tickets

# tshark: look for extremely long ticket validity
tshark -r cap.pcap -Y 'kerberos' -T fields \
  -e ip.src -e kerberos.msg_type -e kerberos.cnameString -e kerberos.till
```

### Network Indicators
- TGS requests for services not normally accessed by that user
- Unusual client names (e.g., `Administrator@DOMAIN.COM` from unexpected host)
- Missing KDC-signed pre-auth in Kerberos exchanges
- Ticket validity far exceeding domain policy (10+ year expiry)

---

## Attack 4: Silver Ticket (T1558.002)

An attacker with the hash of a service account can forge a Service Ticket (ST/TGS) directly — bypassing the KDC entirely. No AS-REQ or TGS-REQ is visible at the network level.

### Detection

```bash
# Key indicator: AP-REQ to a service without any preceding TGS-REQ for that service
# The attacker presents a ticket directly to the service — no KDC interaction

# In network logs: connection to service on expected port,
# but NO corresponding TGS-REQ/REP in kerberos.log for that client→service pair

# Look for Kerberos AP-REQ (msg_type 14) without preceding TGS-REP (msg_type 13)
tshark -r cap.pcap -Y 'kerberos.msg_type == 14' -T fields \
  -e ip.src -e ip.dst -e kerberos.cnameString -e kerberos.sname.name_string

# Compare service connections vs TGS requests for same pairs
# Any service auth without KDC involvement = Silver Ticket suspect
```

---

## Attack 5: Pass-the-Ticket (T1550.003)

An attacker steals a valid Kerberos ticket from memory on a compromised host and presents it from a different host.

### Detection

```bash
# Indicator: Valid Kerberos ticket used from IP different from where it was originally issued
# Hard to detect at network layer alone without endpoint correlation

# Cross-reference:
# 1. Where was TGT issued? (AS-REP destination IP from kerberos.log)
# 2. Where was ST/TGS presented? (AP-REQ source IP)
# If these differ → potential Pass-the-Ticket

zeek-cut ts id.orig_h id.resp_h request_type client < kerberos.log | sort

# Also: Kerberos auth from host where user account has never authenticated before
```

---

## Attack 6: Pass-the-Hash (T1550.002)

An attacker uses a stolen NTLM hash to authenticate without knowing the plaintext password. Visible as NTLM authentication in environments where Kerberos is expected.

### Detection

```bash
# Zeek ntlm.log: flag NTLM where Kerberos should be used
zeek-cut ts id.orig_h id.resp_h success username domain < ntlm.log | \
  awk -F'\t' '$4=="true"' | sort | uniq

# Flag NTLM to domain-joined hosts (should use Kerberos)
# Any NTLM auth over SMB to same-domain hosts is suspicious
zeek-cut id.orig_h id.resp_h < ntlm.log | \
  awk -F'\t' '$1 ~ /^10\.0\./ && $2 ~ /^10\.0\./' | sort | uniq -c | sort -rn

# Suricata: NTLM over SMB
jq 'select(.event_type=="smb") | select(.smb.ntlmssp.type != null)' eve.json

# tshark: extract NTLM authentication
tshark -r cap.pcap -Y 'ntlmssp' -T fields \
  -e ip.src -e ip.dst -e ntlmssp.auth.domain -e ntlmssp.auth.username
```

---

## Response Playbook

```
KERBEROASTING
  □ Identify requesting account (id.orig_h) and service accounts targeted
  □ Force password reset for targeted service accounts (make them >25 chars)
  □ Enable AES-only requirement on service accounts where possible

AS-REP ROASTING
  □ Enable Kerberos preauthentication on all accounts (disable "DONT_REQ_PREAUTH")
  □ Force password reset for affected accounts

GOLDEN TICKET
  □ Rotate KRBTGT password TWICE (24+ hours apart) to invalidate all forged tickets
  □ Identify how KRBTGT hash was obtained (DCSync = T1003.006)
  □ Audit all domain controller access logs

SILVER TICKET
  □ Reset password of targeted service account
  □ Audit service account hash exposure events

PASS-THE-TICKET / PASS-THE-HASH
  □ Isolate affected hosts
  □ Force NTLM block via GPO (require Kerberos for domain communications)
  □ Deploy Credential Guard to prevent hash/ticket theft
```

## Sources

- [SentinelOne — Golden Ticket Detection](https://www.sentinelone.com/blog/mitigation-strategy-kerberos-golden-ticket-attack/)
- [Zeek Kerberos Ticket Tracking PR #92](https://github.com/zeek/zeek/pull/92)
- [EC-Council — Kerberos Offensive Playbook](https://www.eccouncil.org/cybersecurity-exchange/penetration-testing/kerberos-offensive-playbook-enumeration-ticket-abuse/)
- [Medium — Offensive Kerberos for Detection Engineering](https://medium.com/@noah_h/offensive-kerberos-techniques-for-detection-engineering-16a81483f676)
