"""
templating.py — Deterministic log-template mining backed by Drain3.

Pure Python, no LLM calls. Pre-masks dynamic tokens (IPs, UIDs, timestamps, …)
before feeding lines to Drain so that 50 k lines with different IPs collapse to
ONE template.

Usage::

    from agents.shared.templating import premask, TemplateMiner

    masked, params = premask(raw_line)
    miner = TemplateMiner()
    result = miner.add(raw_line)   # {"template_id", "template", "cluster_size", "params"}
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from drain3 import TemplateMiner as _DrainMiner
from drain3.file_persistence import FilePersistence
from drain3.template_miner_config import TemplateMinerConfig

# ---------------------------------------------------------------------------
# Public constant: the full set of placeholder tokens emitted by premask().
# Downstream code (embeddings, store) can reference this to know which tokens
# are "structural wildcards" vs real content.
# ---------------------------------------------------------------------------

EMBED_MASK_TOKENS: set[str] = {
    "<IP>",
    "<UID>",
    "<PORT>",
    "<HEX>",
    "<NUM>",
    "<TS>",
    "<MAC>",
    "<DOMAIN>",
}

# ---------------------------------------------------------------------------
# Pre-compiled regex patterns — ORDER MATTERS (applied top-to-bottom in premask)
# ---------------------------------------------------------------------------

# 1. ISO 8601 / RFC 3339 timestamps  e.g. 2026-07-30T10:00:01Z  2026-07-30 10:00:01.123+00:00
_RE_ISO_TS = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?"
)

# 2. IPv4 followed by :port  e.g. 10.220.5.13:51344  185.220.101.7:443
#    Two capture groups so we can log each part separately.
_RE_IPV4_PORT = re.compile(
    r"(?<![.\d])"
    r"((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))"
    r":"
    r"(\d{1,5})"
    r"(?!\d)"
)

# 3. Bare IPv4 address (not preceded/followed by digit or dot to avoid partial matches)
_RE_IPV4 = re.compile(
    r"(?<![.\d])"
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"(?![.\d])"
)

# 4. Leftover <IP>:port after step 3  (capture group: the port digits)
#    Handles the rare case where step 2 matched the IP but not the :port.
_RE_IP_PORT_LEFTOVER = re.compile(r"<IP>:(\d{1,5})(?!\d)")

# 5. MAC addresses  e.g. 00:1a:2b:3c:4d:5e  or  00-1A-2B-3C-4D-5E
_RE_MAC = re.compile(r"(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}")

# 6. Zeek connection UIDs  e.g. CwXvZ2abcDEfghIJ  (C + 15–20 alphanumeric chars)
_RE_UID = re.compile(r"\bC[a-zA-Z0-9]{15,20}\b")

# 7. Long hex strings / SHA digests  (>= 16 consecutive hex chars)
_RE_HEX = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{16,}(?![0-9a-fA-F])")

# 8. Standalone integers >= 3 digits  (ports, counters, large numbers)
_RE_NUM = re.compile(r"(?<!\d)\d{3,}(?!\d)")

# 9. Domain names  (2+ labels separated by dots; TLD >= 2 alpha chars; no underscores)
#    Applied last so already-masked tokens (<IP> etc.) don't partially match.
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)


# ---------------------------------------------------------------------------
# premask
# ---------------------------------------------------------------------------


def premask(raw: str) -> tuple[str, dict[str, list[str]]]:
    """Deterministically mask dynamic tokens BEFORE Drain.

    Replaces IP addresses, UIDs, timestamps, MAC addresses, hex strings,
    large integers, and domain names with stable placeholder tokens so that
    many structurally identical log lines with different field values collapse
    to a single Drain template.

    Masking priority (longest/most-specific first to avoid partial clobbering):
      1. ISO timestamps         → <TS>
      2. IPv4:port              → <IP>:<PORT>
      3. bare IPv4              → <IP>
      4. leftover <IP>:digits   → <IP>:<PORT>
      5. MAC addresses          → <MAC>
      6. Zeek UIDs (C+15-20)    → <UID>
      7. long hex (>=16 chars)  → <HEX>
      8. integers >= 3 digits   → <NUM>
      9. domain names           → <DOMAIN>

    Returns:
        (masked_string, params_dict)

    ``params_dict`` maps each placeholder token that was used (e.g. ``"<IP>"``)
    to the ordered list of original values it replaced in this line.
    """
    captured: dict[str, list[str]] = defaultdict(list)

    def _sub(tok: str) -> Any:
        """Return a re.sub replacement function that records the match."""
        def _fn(m: re.Match) -> str:  # type: ignore[type-arg]
            captured[tok].append(m.group(0))
            return tok
        return _fn

    s = raw

    # 1. ISO timestamps
    s = _RE_ISO_TS.sub(_sub("<TS>"), s)

    # 2. IPv4:port  (two groups, so we capture ip and port separately)
    def _ipv4_port_fn(m: re.Match) -> str:  # type: ignore[type-arg]
        captured["<IP>"].append(m.group(1))
        captured["<PORT>"].append(m.group(2))
        return "<IP>:<PORT>"

    s = _RE_IPV4_PORT.sub(_ipv4_port_fn, s)

    # 3. Bare IPv4
    s = _RE_IPV4.sub(_sub("<IP>"), s)

    # 4. Leftover <IP>:digits → <IP>:<PORT>
    def _leftover_port_fn(m: re.Match) -> str:  # type: ignore[type-arg]
        captured["<PORT>"].append(m.group(1))
        return "<IP>:<PORT>"

    s = _RE_IP_PORT_LEFTOVER.sub(_leftover_port_fn, s)

    # 5. MAC addresses
    s = _RE_MAC.sub(_sub("<MAC>"), s)

    # 6. Zeek UIDs
    s = _RE_UID.sub(_sub("<UID>"), s)

    # 7. Long hex strings
    s = _RE_HEX.sub(_sub("<HEX>"), s)

    # 8. Standalone integers >= 3 digits
    s = _RE_NUM.sub(_sub("<NUM>"), s)

    # 9. Domain names
    s = _RE_DOMAIN.sub(_sub("<DOMAIN>"), s)

    return s, dict(captured)


# ---------------------------------------------------------------------------
# TemplateMiner
# ---------------------------------------------------------------------------


class TemplateMiner:
    """Drain3-backed log template miner with deterministic pre-masking.

    Args:
        state_path: Optional path for persistent Drain state (FilePersistence).
                    When *None* the miner is in-memory only.

    The miner pre-masks each raw line via :func:`premask` before handing it
    to Drain, so dynamic tokens (IPs, UIDs, …) are already normalised and
    Drain's own numeric parameterisation is disabled (we own that step).
    """

    def __init__(self, state_path: str | None = None) -> None:
        config = TemplateMinerConfig()
        config.drain_sim_th = 0.4
        config.drain_depth = 4
        config.drain_max_children = 100
        # We pre-mask everything ourselves; disable Drain's built-in masking.
        config.masking_instructions = []
        # Drain's numeric-token parameterisation is redundant after premask;
        # disable it so our <NUM> tokens are kept as literal cluster tokens.
        config.parametrize_numeric_tokens = False

        persistence: FilePersistence | None = None
        if state_path is not None:
            persistence = FilePersistence(state_path)

        self._miner = _DrainMiner(
            persistence_handler=persistence,
            config=config,
        )

        # Internal metadata per template_id (str).
        # { template_id: {"template": str, "count": int, "sample": str, "mask_keys": dict} }
        self._meta: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add(self, raw: str) -> dict[str, Any]:
        """Pre-mask *raw*, feed to Drain, and return the cluster metadata.

        Returns a dict with keys:
            ``template_id``  — stable string ID for the matched template.
            ``template``     — the Drain template string (wildcards shown as ``<*>``).
            ``cluster_size`` — total number of log lines in this cluster so far.
            ``params``       — the :func:`premask` params dict for this line.
        """
        masked, params = premask(raw)
        result = self._miner.add_log_message(masked)

        tid = str(result["cluster_id"])
        cluster = self._miner.drain.id_to_cluster[result["cluster_id"]]
        template = cluster.get_template()
        size = cluster.size

        if tid not in self._meta:
            self._meta[tid] = {
                "template": template,
                "count": size,
                "sample": raw,
                "mask_keys": params,
            }
        else:
            # Update mutable fields; keep the original sample.
            self._meta[tid]["template"] = template
            self._meta[tid]["count"] = size

        return {
            "template_id": tid,
            "template": template,
            "cluster_size": size,
            "params": params,
        }

    def match(self, raw: str) -> dict[str, Any] | None:
        """Non-mutating lookup: return cluster metadata if *raw* matches, else None.

        Does NOT create or grow clusters.
        """
        masked, params = premask(raw)
        cluster = self._miner.match(masked)
        if cluster is None:
            return None

        tid = str(cluster.cluster_id)
        return {
            "template_id": tid,
            "template": cluster.get_template(),
            "cluster_size": cluster.size,
            "params": params,
        }

    def templates(self) -> list[dict[str, Any]]:
        """Return a snapshot of all known templates.

        Each entry has keys:
            ``template_id``, ``template``, ``cluster_size``, ``sample``.
        """
        out: list[dict[str, Any]] = []
        for cid, cluster in self._miner.drain.id_to_cluster.items():
            tid = str(cid)
            meta = self._meta.get(tid, {})
            out.append(
                {
                    "template_id": tid,
                    "template": cluster.get_template(),
                    "cluster_size": cluster.size,
                    "sample": meta.get("sample", ""),
                }
            )
        return out
