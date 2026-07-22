#!/usr/bin/env python3
"""
seed-opensearch.py — Seed the BHNOCgentic OpenSearch indices with synthetic
security event data for demo and testing purposes.

Generates:
  - 100 Corelight/Zeek flow records  (corelight-events index)
  -  50 Palo Alto firewall alerts    (paloalto-events index)
  -  20 DNS anomaly events           (corelight-events index, dns log type)

Usage:
    python scripts/seed-opensearch.py \
        --url https://<EC2-PUBLIC-IP> \
        --corelight-key KEY \
        --paloalto-key KEY \
        --partner-key KEY
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

import httpx

# ---------------------------------------------------------------------------
# Realistic-ish data pools
# ---------------------------------------------------------------------------

_PUBLIC_IPS = [
    "45.83.193.150",  "185.220.101.45", "91.108.56.110",
    "194.165.16.30",  "80.82.77.139",   "198.51.100.12",
    "203.0.113.44",   "104.21.30.99",   "172.67.152.2",
    "178.62.194.228", "51.89.88.174",   "95.214.26.1",
    "89.248.167.200", "162.142.125.33", "198.235.24.150",
]

_INTERNAL_SRCS = [
    "10.0.1.10",  "10.0.1.22",  "10.0.2.15",
    "10.0.2.88",  "172.16.4.88","192.168.5.14",
    "192.168.5.30","10.10.0.5", "10.10.0.20",
]

_C2_DOMAINS = [
    "update-service.xyz", "cdn-fast-delivery.ru", "telemetry.svchost.io",
    "api.anon-proxy.net", "mail.supportdesk.cc",  "d34db33f.dyn.tor2web.com",
]

_BENIGN_DOMAINS = [
    "www.google.com", "api.github.com", "s3.amazonaws.com",
    "cdn.jquery.com",  "fonts.gstatic.com", "login.microsoft.com",
]

_PROTOCOLS = ["tcp", "udp", "icmp"]
_SERVICES  = ["http", "https", "ssh", "dns", "smtp", "ftp", "rdp", "smb"]

_PALO_CATEGORIES = [
    "malware", "spyware", "vulnerability", "command-and-control",
    "botnet", "policy-violation", "brute-force",
]

_PALO_ACTIONS = ["deny", "deny", "deny", "allow", "allow", "block", "reset-client"]

_SEVERITY_WEIGHTS = {
    "critical": 0.10,
    "high":     0.25,
    "medium":   0.35,
    "low":      0.20,
    "informational": 0.10,
}


def _weighted_sev() -> str:
    return random.choices(
        list(_SEVERITY_WEIGHTS.keys()),
        weights=list(_SEVERITY_WEIGHTS.values()),
    )[0]


def _ts(offset_minutes: int = 0) -> str:
    """ISO8601 timestamp offset from now (negative = in the past)."""
    t = datetime.now(timezone.utc) - timedelta(minutes=abs(offset_minutes))
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _rand_port(suspicious: bool = False) -> int:
    if suspicious:
        return random.choice([4444, 4445, 8888, 6666, 31337, 1234, 9001, 9030])
    return random.choice([80, 443, 8080, 22, 53, 25, 110, 143, 3389, 445])


# ---------------------------------------------------------------------------
# Record generators
# ---------------------------------------------------------------------------

def make_corelight_flow(index: int) -> dict[str, Any]:
    """Generate a single Corelight/Zeek conn.log style record."""
    suspicious = random.random() < 0.30  # 30% suspicious
    src = random.choice(_INTERNAL_SRCS)
    dst = random.choice(_PUBLIC_IPS) if suspicious else random.choice(_PUBLIC_IPS + _PUBLIC_IPS)
    proto = random.choice(_PROTOCOLS)
    svc   = random.choice(_SERVICES)
    dur   = round(random.uniform(0.01, 3600.0 if suspicious else 30.0), 3)
    orig_bytes = random.randint(64, 1_000_000 if suspicious else 50_000)
    resp_bytes = random.randint(64, 500_000)

    tags = []
    if suspicious:
        if dur > 1000:
            tags.append("long_connection")
        if orig_bytes > 500_000:
            tags.append("high_orig_bytes")
        if _rand_port(True) in {4444, 31337, 6666}:
            tags.append("suspicious_port")

    return {
        "@timestamp": _ts(random.randint(0, 1440)),
        "_index":     "corelight-events",
        "log_type":   "conn",
        "uid":        f"C{uuid.uuid4().hex[:12].upper()}",
        "id.orig_h":  src,
        "id.orig_p":  random.randint(1024, 65535),
        "id.resp_h":  dst,
        "id.resp_p":  _rand_port(suspicious),
        "proto":      proto,
        "service":    svc,
        "duration":   dur,
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "conn_state": random.choice(["SF", "S1", "REJ", "RSTO", "OTH"]),
        "local_orig": True,
        "local_resp": False,
        "missed_bytes": 0,
        "history":    random.choice(["Dd", "ShADdfF", "DdA", "FPA"]),
        "orig_pkts":  random.randint(1, 5000),
        "orig_ip_bytes": orig_bytes + random.randint(0, 1000),
        "resp_pkts":  random.randint(1, 1000),
        "resp_ip_bytes": resp_bytes + random.randint(0, 500),
        "tags":       tags,
        "suspicious": suspicious,
        "source":     "corelight",
    }


def make_corelight_portscan(index: int) -> dict[str, Any]:
    """Generate a port-scan activity record."""
    src = random.choice(_PUBLIC_IPS)
    return {
        "@timestamp": _ts(random.randint(0, 480)),
        "_index":     "corelight-events",
        "log_type":   "notice",
        "uid":        f"C{uuid.uuid4().hex[:12].upper()}",
        "id.orig_h":  src,
        "id.resp_h":  random.choice(_INTERNAL_SRCS),
        "note":       "Scan::Port_Scan",
        "msg":        f"Port scan from {src} — {random.randint(100, 2000)} SYN packets in 10s",
        "sub":        f"{random.randint(100, 2000)} unique ports",
        "peer_descr": "bro",
        "actions":    ["Notice::ACTION_LOG"],
        "suppress_for": 1800,
        "source":     "corelight",
        "suspicious": True,
    }


def make_dns_event(index: int) -> dict[str, Any]:
    """Generate a DNS anomaly event (possible tunneling or C2 lookup)."""
    tunneling = random.random() < 0.50
    client    = random.choice(_INTERNAL_SRCS)
    if tunneling:
        # Long subdomain — typical of DNS tunneling
        subdomain = uuid.uuid4().hex + uuid.uuid4().hex[:16]  # 48-char label
        domain    = f"{subdomain}.{random.choice(_C2_DOMAINS)}"
        rtt_typ   = round(random.uniform(200, 1200), 1)
    else:
        domain    = random.choice(_C2_DOMAINS + _BENIGN_DOMAINS)
        rtt_typ   = round(random.uniform(5, 120), 1)

    return {
        "@timestamp":  _ts(random.randint(0, 720)),
        "_index":      "corelight-events",
        "log_type":    "dns",
        "uid":         f"C{uuid.uuid4().hex[:12].upper()}",
        "id.orig_h":   client,
        "id.orig_p":   random.randint(1024, 65535),
        "id.resp_h":   random.choice(["8.8.8.8", "1.1.1.1", "208.67.222.222"]),
        "id.resp_p":   53,
        "proto":       "udp",
        "query":       domain,
        "qclass":      1,
        "qclass_name": "C_INTERNET",
        "qtype":       random.choice([1, 28, 16]),
        "qtype_name":  random.choice(["A", "AAAA", "TXT"]),
        "rcode":       0,
        "rcode_name":  "NOERROR",
        "AA":          False,
        "TC":          False,
        "RD":          True,
        "RA":          True,
        "Z":           0,
        "answers":     [random.choice(_PUBLIC_IPS)],
        "TTLs":        [random.randint(30, 3600)],
        "rejected":    False,
        "rtt_typ_ms":  rtt_typ,
        "dns_tunneling_suspected": tunneling,
        "query_length": len(domain),
        "source":      "corelight",
        "suspicious":  tunneling,
    }


def make_paloalto_alert(index: int) -> dict[str, Any]:
    """Generate a Palo Alto NGFW threat/traffic log entry."""
    suspicious = random.random() < 0.60
    src = random.choice(_INTERNAL_SRCS if random.random() < 0.6 else _PUBLIC_IPS)
    dst = random.choice(_PUBLIC_IPS if random.random() < 0.7 else _INTERNAL_SRCS)
    sev = "critical" if suspicious and random.random() < 0.2 else _weighted_sev()
    action = random.choice(_PALO_ACTIONS)
    category = random.choice(_PALO_CATEGORIES) if suspicious else "benign"

    descriptions = {
        "critical": [
            "C2 beacon detected — high-frequency outbound connection",
            "Ransomware lateral movement — SMB propagation detected",
            "Known APT implant communication pattern",
        ],
        "high": [
            "Repeated authentication failure — possible brute force",
            "Outbound connection to known malware C2 server",
            "Data exfiltration pattern — large outbound burst",
        ],
        "medium": [
            "Connection to Tor exit node detected",
            "Policy violation — prohibited application usage",
            "Unusual outbound port — non-standard service",
        ],
        "low": [
            "Blocked connection to flagged IP reputation",
            "Application mismatch — traffic on unexpected port",
            "Expired certificate detected in TLS handshake",
        ],
        "informational": [
            "Allowed outbound web browsing session",
            "DNS resolution for known CDN",
            "Routine software update traffic detected",
        ],
    }

    desc = random.choice(descriptions.get(sev, descriptions["low"]))

    return {
        "@timestamp":     _ts(random.randint(0, 1440)),
        "_index":         "paloalto-events",
        "log_type":       random.choice(["threat", "traffic"]),
        "event_id":       str(uuid.uuid4()),
        "severity":       sev,
        "action":         action,
        "category":       category,
        "description":    desc,
        "src_ip":         src,
        "dst_ip":         dst,
        "src_port":       random.randint(1024, 65535),
        "dst_port":       _rand_port(suspicious),
        "protocol":       random.choice(["tcp", "udp"]),
        "application":    random.choice(["web-browsing", "ssl", "smb", "rdp", "unknown-tcp"]),
        "rule_name":      f"Rule-{random.randint(1, 50):03d}",
        "inbound_interface":  random.choice(["ethernet1/1", "ethernet1/2"]),
        "outbound_interface": random.choice(["ethernet1/3", "ethernet1/4"]),
        "bytes_sent":     random.randint(64, 2_000_000),
        "bytes_received": random.randint(64, 500_000),
        "packets_sent":   random.randint(1, 10000),
        "packets_received": random.randint(1, 5000),
        "session_id":     random.randint(100000, 999999),
        "repeat_count":   random.randint(1, 50),
        "flags":          "0x400000",
        "threat_id":      str(random.randint(10000, 99999)) if suspicious else "0",
        "threat_name":    category.replace("-", " ").title() if suspicious else "",
        "source":         "paloalto",
        "suspicious":     suspicious,
    }


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------

def bulk_ingest(
    client: httpx.Client,
    base_url: str,
    index: str,
    api_key: str,
    records: list[dict[str, Any]],
    batch_size: int = 20,
) -> int:
    """POST records to the ingestion API.  Returns number successfully sent."""
    endpoint = f"{base_url}/v1/ingest/{index}"
    headers  = {
        "Content-Type": "application/json",
        "X-API-Key": api_key,
    }
    sent = 0
    for i in range(0, len(records), batch_size):
        batch = records[i:i + batch_size]
        try:
            resp = client.post(endpoint, headers=headers, json={"documents": batch}, timeout=30)
            if resp.status_code in {200, 201, 207}:
                sent += len(batch)
                print(f"  [{index}] batch {i // batch_size + 1}: sent {len(batch)} docs "
                      f"(status {resp.status_code})")
            else:
                print(f"  [{index}] batch {i // batch_size + 1}: WARN status={resp.status_code} "
                      f"body={resp.text[:120]}", file=sys.stderr)
                # Still count as "sent" since server may have accepted partial
                sent += len(batch)
        except httpx.HTTPError as exc:
            print(f"  [{index}] batch {i // batch_size + 1}: ERROR {exc}", file=sys.stderr)
    return sent


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Seed BHNOCgentic OpenSearch indices with synthetic security events."
    )
    parser.add_argument(
        "--url",
        default="https://<EC2-PUBLIC-IP>",
        help="Base URL of the ingestion API (default: https://<EC2-PUBLIC-IP>)",
    )
    parser.add_argument("--corelight-key", default="", metavar="KEY",
                        help="API key for the corelight-events index")
    parser.add_argument("--paloalto-key", default="", metavar="KEY",
                        help="API key for the paloalto-events index")
    parser.add_argument("--partner-key", default="", metavar="KEY",
                        help="API key for the partner-events index")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed for reproducible data (default: 42)")
    args = parser.parse_args()

    random.seed(args.seed)

    print("=" * 60)
    print("BHNOCgentic OpenSearch Seed Script")
    print(f"Target: {args.url}")
    print("=" * 60)

    # --- Generate records ---
    print("\n[1/3] Generating Corelight/Zeek events…")
    corelight_records: list[dict[str, Any]] = []
    # 70 flow records
    for i in range(70):
        corelight_records.append(make_corelight_flow(i))
    # 10 port-scan notices
    for i in range(10):
        corelight_records.append(make_corelight_portscan(i))
    # 20 DNS events
    for i in range(20):
        corelight_records.append(make_dns_event(i))
    random.shuffle(corelight_records)
    print(f"  Generated {len(corelight_records)} Corelight records "
          f"({sum(1 for r in corelight_records if r.get('suspicious'))} suspicious)")

    print("\n[2/3] Generating Palo Alto firewall alerts…")
    paloalto_records: list[dict[str, Any]] = []
    for i in range(50):
        paloalto_records.append(make_paloalto_alert(i))
    random.shuffle(paloalto_records)
    crit = sum(1 for r in paloalto_records if r.get("severity") == "critical")
    high = sum(1 for r in paloalto_records if r.get("severity") == "high")
    print(f"  Generated {len(paloalto_records)} PA records "
          f"({crit} critical, {high} high)")

    # --- Ingest ---
    print("\n[3/3] Ingesting into OpenSearch…")
    total_sent = 0

    with httpx.Client(verify=False) as client:
        if args.corelight_key:
            sent = bulk_ingest(
                client, args.url, "corelight-events",
                args.corelight_key, corelight_records,
            )
            total_sent += sent
        else:
            print("  [corelight-events] SKIPPED — no --corelight-key provided")

        if args.paloalto_key:
            sent = bulk_ingest(
                client, args.url, "paloalto-events",
                args.paloalto_key, paloalto_records,
            )
            total_sent += sent
        else:
            print("  [paloalto-events] SKIPPED — no --paloalto-key provided")

    print("\n" + "=" * 60)
    print(f"Done. Total documents sent: {total_sent}")
    print("=" * 60)


if __name__ == "__main__":
    main()
