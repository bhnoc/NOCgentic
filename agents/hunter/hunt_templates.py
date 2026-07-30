"""
hunt_templates.py — Built-in MITRE-mapped threat hunt templates for NOCgentic.

Each template is a dict with a stable slug id, MITRE tactic/technique, a
hypothesis, and a natural-language hunt_query for the investigator (NL->SQL
over Corelight/Suricata Athena tables: conn, dns, http, ssl,
suricata_corelight, notice, weird; columns: id_orig_h, id_resp_h,
alert_signature, orig_bytes, dt, ts).

No raw SQL or CQL — the investigator translates NL to Athena SQL.
"""

HUNT_TEMPLATES: list[dict] = [
    {
        "id": "c2-non-standard-port",
        "name": "C2 on non-standard ports",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1571 Non-Standard Port",
        "hypothesis": (
            "Beaconing or C2 often rides uncommon ports to evade detection. "
            "Internal hosts making repeated low-volume outbound connections to "
            "fixed external IPs on non-standard ports may indicate an implant."
        ),
        "hunt_query": (
            "Over the last 24h, find internal hosts making repeated outbound "
            "connections to external IPs on non-standard ports (not 80, 443, or 53). "
            "Flag any with regular timing intervals or high connection counts that "
            "look like C2 beaconing. Use the conn table; filter orig_bytes for "
            "low steady-state traffic patterns."
        ),
        "enabled": True,
        "interval_hours": 6,
    },
    {
        "id": "c2-encrypted-channel",
        "name": "Encrypted C2 channel (non-standard TLS)",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1573 Encrypted Channel",
        "hypothesis": (
            "Adversaries tunnel C2 over TLS to blend in, but self-signed or "
            "unusual-issuer certificates on non-web ports are a strong indicator."
        ),
        "hunt_query": (
            "Over the last 24h, find SSL/TLS connections from internal hosts to "
            "external destinations on ports other than 443 where the certificate "
            "issuer is unknown, self-signed, or the subject does not match a "
            "known SaaS or CDN. Use the ssl table; look for short-lived or "
            "high-frequency sessions with small payload sizes."
        ),
        "enabled": True,
        "interval_hours": 6,
    },
    {
        "id": "exfil-large-outbound",
        "name": "Large outbound data transfer (potential exfiltration)",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1030 Data Transfer Size Limits",
        "hypothesis": (
            "Exfiltration often involves sustained or bursty large outbound "
            "transfers to external IPs. Internal hosts sending unusually large "
            "volumes warrant review."
        ),
        "hunt_query": (
            "Over the last 24h, identify internal hosts that have sent more than "
            "100 MB of data to a single external IP or domain. Use the conn table "
            "with orig_bytes; group by id_orig_h and id_resp_h. Flag transfers "
            "that are unusually large compared to typical baseline, especially "
            "outside business hours or to IPs with no prior connection history."
        ),
        "enabled": True,
        "interval_hours": 24,
    },
    {
        "id": "discovery-port-scan",
        "name": "Internal network service discovery (port scanning)",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1046 Network Service Discovery",
        "hypothesis": (
            "An attacker who has gained a foothold will scan the internal network "
            "to discover services. A single host probing many distinct ports or "
            "hosts in a short window is a strong indicator."
        ),
        "hunt_query": (
            "Over the last 24h, find internal hosts that connected to more than "
            "20 distinct ports or more than 50 distinct internal destination IPs. "
            "Use the conn table; look for short-duration connections with minimal "
            "data transfer (orig_bytes near zero) indicative of port scanning. "
            "Also check the notice and weird tables for scan alerts."
        ),
        "enabled": True,
        "interval_hours": 6,
    },
    {
        "id": "lateral-movement-smb-rdp",
        "name": "Lateral movement via SMB or RDP after initial foothold",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1210 Exploitation of Remote Services",
        "hypothesis": (
            "After gaining an initial foothold, adversaries move laterally via "
            "SMB (port 445) or RDP (port 3389). Internal-to-internal traffic on "
            "these ports from non-admin hosts or in unusual patterns is suspicious."
        ),
        "hunt_query": (
            "Over the last 24h, find internal-to-internal connections on port 445 "
            "or 3389 where the originating host is not a known jump server or "
            "admin workstation. Use the conn table; flag hosts that initiated "
            "SMB or RDP connections to multiple internal destinations, especially "
            "if followed by Suricata alerts in the suricata_corelight table. "
            "Look for authentication failure patterns in the notice or weird tables."
        ),
        "enabled": True,
        "interval_hours": 6,
    },
    {
        "id": "initial-access-external-remote",
        "name": "External access to remote services (RDP, SSH, VPN)",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1133 External Remote Services",
        "hypothesis": (
            "Attackers exploit externally exposed RDP, SSH, or VPN endpoints for "
            "initial access. Inbound connections from external IPs on these ports, "
            "especially from unusual geographies or with authentication failures, "
            "warrant investigation."
        ),
        "hunt_query": (
            "Over the last 24h, find inbound connections from external IPs to "
            "internal hosts on port 22 (SSH), 3389 (RDP), or VPN ports (1194, "
            "4500, 500). Use the conn table; flag sources with more than 5 failed "
            "connection attempts or sources appearing for the first time. Check "
            "the notice and suricata_corelight tables for brute-force or exploit "
            "signatures on these ports."
        ),
        "enabled": True,
        "interval_hours": 6,
    },
    {
        "id": "credential-brute-force",
        "name": "Credential brute force against internal services",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110 Brute Force",
        "hypothesis": (
            "Repeated authentication failures against a single service from a "
            "single source indicate credential stuffing or brute force. This "
            "applies to both external sources and compromised internal hosts."
        ),
        "hunt_query": (
            "Over the last 24h, identify sources (internal or external) that "
            "made more than 10 connection attempts to the same destination on "
            "authentication-bearing ports (22, 23, 25, 110, 143, 389, 443, "
            "445, 3389, 5900). Use the conn table; also check the "
            "suricata_corelight table for brute-force alert signatures and the "
            "notice table for scan or brute-force notices. Flag sources with "
            "high connection counts and low orig_bytes per connection."
        ),
        "enabled": True,
        "interval_hours": 6,
    },
]
