"""Gate: demo and seed fixtures must use in-scope conference addresses.

QA sweep finding: every seeded INTERNAL_IP and 4 of 6 hardcoded UI demo alerts
were out of scope under the allowlist, so any environment without live conference
data rendered [OUT-OF-SCOPE-IP] everywhere and the app looked broken.

Public addresses in demo data are intentional (they play the threat actors and are
shown by design), so only the internal fixtures are checked.
"""

import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "agents", "shared"))

import ipscope  # noqa: E402

_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")


def test_seeded_internal_ips_are_in_scope():
    src = open(os.path.join(_ROOT, "scripts", "seed-s3.py")).read()
    block = re.search(r"INTERNAL_IPS\s*=\s*\[(.*?)\]", src, re.S)
    assert block, "INTERNAL_IPS not found in scripts/seed-s3.py"
    ips = re.findall(r'"(\d+\.\d+\.\d+\.\d+)"', block.group(1))
    assert ips, "no IPs parsed from INTERNAL_IPS"
    out_of_scope = [i for i in ips if not ipscope.is_in_scope(i)]
    assert not out_of_scope, f"seeded internal IPs redact to a placeholder: {out_of_scope}"


def test_ui_demo_alert_ips_are_in_scope_or_public():
    path = os.path.join(_ROOT, "packages", "web-server", "static", "index.html")
    html = open(path).read()
    ips = re.findall(r"srcIp:'(\d+\.\d+\.\d+\.\d+)'", html)
    assert ips, "no demo srcIp literals found"
    out_of_scope = [i for i in ips if not ipscope.is_in_scope(i)]
    assert not out_of_scope, f"UI demo alerts would render redacted: {out_of_scope}"


def test_demo_ticker_generates_public_addresses():
    """randomIp() plays external attackers; those must stay visible."""
    path = os.path.join(_ROOT, "packages", "web-server", "static", "index.html")
    html = open(path).read()
    block = re.search(r"function randomIp\(\)\s*\{(.*?)\}", html, re.S)
    assert block, "randomIp() not found"
    prefixes = re.findall(r"'(\d+\.\d+\.)'", block.group(1))
    assert prefixes, "no prefixes parsed from randomIp()"
    for prefix in prefixes:
        assert ipscope.is_in_scope(prefix + "10.10"), f"{prefix}x.x would be redacted"
