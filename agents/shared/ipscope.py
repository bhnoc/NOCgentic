"""Canonical IP scope policy for the Black Hat NOC.

Single source of truth for "which addresses may appear in user-facing output".
Every agent imports from here; do NOT re-implement the check locally.

Policy (allowlist, default-deny):
  * In-scope conference subnets  -> shown verbatim (investigation subjects)
  * Publicly routable addresses  -> shown verbatim (threat actors, C2, intel)
  * Everything else private      -> redacted to [OUT-OF-SCOPE-IP]

"Everything else private" deliberately includes loopback, link-local
(169.254.0.0/16 — the EC2 metadata endpoint), CGNAT (100.64/10), and any
10./172.16./192.168. address outside the conference ranges. Those are either
infrastructure detail or someone else's network; neither belongs in the UI.

This replaces five hand-rolled per-agent regexes that shared one octet suffix
across their private-range branches, leaving 10/8 an octet short and leaking the
final octet (10.0.1.63 -> "[INTERNAL-IP].63"). Matching every IPv4 literal and
deciding with `ipaddress` containment makes that class of bug impossible.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable

__all__ = [
    "IN_SCOPE_NETWORKS",
    "OUT_OF_SCOPE_PLACEHOLDER",
    "is_in_scope",
    "redact_text",
    "redact_obj",
    "row_in_scope",
    "filter_rows",
]

OUT_OF_SCOPE_PLACEHOLDER = "[OUT-OF-SCOPE-IP]"

# Conference ranges, as supplied by the NOC lead 2026-07-31.
#   * 10.220.30.0/25 is a HALF range (.0-.127), not a /24.
#   * 10.220.73.0/24 is absent by design ("n/a - reusing 72").
#   * 10.220.147 is the last in-scope third octet.
_CONFERENCE_CIDRS: tuple[str, ...] = (
    "10.220.30.0/25",
    *(f"10.220.{third}.0/24" for third in range(31, 73)),
    *(f"10.220.{third}.0/24" for third in range(74, 148)),
    "192.168.128.0/18",
)

IN_SCOPE_NETWORKS: tuple[ipaddress.IPv4Network, ...] = tuple(
    ipaddress.ip_network(c) for c in _CONFERENCE_CIDRS
)

# Any dotted quad. Intentionally broad: candidates are parsed and range-checked
# rather than pattern-trusted, so a sloppy match cannot cause a partial redact.
_IPV4_CANDIDATE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def is_in_scope(value: str) -> bool:
    """True if this address may be shown to users.

    Unparseable input returns False: if we cannot prove an address is safe to
    display, we do not display it.
    """
    try:
        addr = ipaddress.ip_address(value.strip())
    except (ValueError, AttributeError):
        return False
    if any(addr in net for net in IN_SCOPE_NETWORKS):
        return True
    # is_global is precisely "publicly routable" — excludes private, loopback,
    # link-local and CGNAT without enumerating them.
    return bool(addr.is_global)


def redact_text(text: str) -> str:
    """Replace every out-of-scope IPv4 literal in free text."""
    if not isinstance(text, str) or not text:
        return text

    def _sub(match: re.Match[str]) -> str:
        candidate = match.group(0)
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            # Not a real address (e.g. a version string like 1.2.3.400) — leave it.
            return candidate
        return candidate if is_in_scope(candidate) else OUT_OF_SCOPE_PLACEHOLDER

    return _IPV4_CANDIDATE.sub(_sub, text)


def redact_obj(obj: Any) -> Any:
    """Recursively redact out-of-scope IPs in any JSON-compatible structure."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(redact_obj(v) for v in obj)
    return obj


# Athena column names that carry an endpoint address, either direction.
_ADDRESS_FIELDS: tuple[str, ...] = (
    "id_orig_h",
    "id_resp_h",
    "orig_h",
    "resp_h",
    "srcIp",
    "dstIp",
    "src_ip",
    "dst_ip",
    "host_ip",
    "query_ip",
)


def row_in_scope(row: dict[str, Any]) -> bool:
    """True if every populated address field on this row is in scope.

    Both directions must qualify: a flow from an out-of-scope private host is
    not ours to show even when the peer is a legitimate public address.
    """
    for field in _ADDRESS_FIELDS:
        value = row.get(field)
        if value in (None, "", "-"):
            continue
        if not is_in_scope(str(value)):
            return False
    return True


def filter_rows(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop rows touching an out-of-scope address (egress row-level filter)."""
    return [r for r in rows if row_in_scope(r)]
