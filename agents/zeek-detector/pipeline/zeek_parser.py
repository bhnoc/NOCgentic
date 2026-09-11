"""
Zeek Log Parser — parses ssl.log and conn.log in TSV and JSON formats.

Zeek TSV format:
  - Lines starting with '#' are metadata/comments
  - '#fields' line defines column names
  - '#types' line defines column types
  - '#separator' defines field separator (usually \x09 = tab)

Output schema (normalized event):
  {
    "ts": float,          # Unix timestamp
    "uid": str,           # Connection UID
    "src_host": str,      # Source IP
    "src_port": int,
    "dst_host": str,      # Destination IP
    "dst_port": int,
    "proto": str,         # tcp/udp/icmp
    "service": str | None,
    "duration": float | None,
    "bytes_sent": int | None,
    "bytes_recv": int | None,
    "state": str | None,  # conn state
    "log_type": str,      # "ssl" or "conn"
    # SSL-specific fields:
    "server_name": str | None,
    "version": str | None,
    "cipher": str | None,
    "established": bool | None,
  }
"""

import json
from pathlib import Path
from typing import Iterator, Optional
from collections import defaultdict


ZEEK_UNSET = {"-", "(empty)", "", "\\N"}


def _parse_val(v: str, typ: str = "string"):
    """Convert a raw TSV cell to a typed Python value."""
    if v in ZEEK_UNSET:
        return None
    if typ in ("time", "interval", "double"):
        try:
            return float(v)
        except ValueError:
            return None
    if typ in ("count", "int", "port"):
        try:
            return int(v)
        except ValueError:
            return None
    if typ == "bool":
        return v.upper() == "T"
    return v  # string


def _parse_tsv_log(lines: Iterator[str], log_type: str) -> Iterator[dict]:
    """Parse a Zeek TSV log file, yielding raw field dicts."""
    separator = "\t"
    fields: list[str] = []
    types: list[str] = []

    for raw in lines:
        line = raw.rstrip("\n")
        if line.startswith("#separator"):
            # e.g. "#separator \x09"
            sep_val = line.split(None, 1)[1]
            separator = sep_val.encode().decode("unicode_escape")
        elif line.startswith("#fields"):
            fields = line[len("#fields"):].lstrip(separator).split(separator)
        elif line.startswith("#types"):
            types = line[len("#types"):].lstrip(separator).split(separator)
        elif line.startswith("#"):
            continue  # skip other metadata lines
        elif fields:
            cells = line.split(separator)
            if len(cells) != len(fields):
                continue
            row: dict = {}
            for i, fname in enumerate(fields):
                typ = types[i] if i < len(types) else "string"
                row[fname] = _parse_val(cells[i], typ)
            row["_log_type"] = log_type
            yield row


def _parse_json_log(lines: Iterator[str], log_type: str) -> Iterator[dict]:
    """Parse a Zeek JSON log (one JSON object per line)."""
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            obj["_log_type"] = log_type
            yield obj
        except json.JSONDecodeError:
            continue


def _normalize_conn(raw: dict) -> dict:
    """Normalize a conn.log raw row to the standard event schema."""
    return {
        "ts": raw.get("ts"),
        "uid": raw.get("uid"),
        "src_host": raw.get("id.orig_h"),
        "src_port": raw.get("id.orig_p"),
        "dst_host": raw.get("id.resp_h"),
        "dst_port": raw.get("id.resp_p"),
        "proto": raw.get("proto"),
        "service": raw.get("service"),
        "duration": raw.get("duration"),
        "bytes_sent": _to_int(raw.get("orig_bytes")),
        "bytes_recv": _to_int(raw.get("resp_bytes")),
        "state": raw.get("conn_state"),
        "log_type": "conn",
        "server_name": None,
        "version": None,
        "cipher": None,
        "established": None,
    }


def _normalize_ssl(raw: dict) -> dict:
    """Normalize an ssl.log raw row to the standard event schema."""
    established = raw.get("established")
    if isinstance(established, str):
        established = established.upper() == "T"
    return {
        "ts": raw.get("ts"),
        "uid": raw.get("uid"),
        "src_host": raw.get("id.orig_h"),
        "src_port": raw.get("id.orig_p"),
        "dst_host": raw.get("id.resp_h"),
        "dst_port": raw.get("id.resp_p"),
        "proto": "tcp",
        "service": "ssl",
        "duration": None,
        "bytes_sent": None,
        "bytes_recv": None,
        "state": None,
        "log_type": "ssl",
        "server_name": raw.get("server_name"),
        "version": raw.get("version"),
        "cipher": raw.get("cipher"),
        "established": established,
    }


def _to_int(v) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(v)
    except (ValueError, TypeError):
        return None


def _detect_format(lines: list[str]) -> str:
    """Return 'tsv' or 'json' based on the first non-empty line."""
    for line in lines:
        stripped = line.strip()
        if stripped:
            if stripped.startswith("{"):
                return "json"
            return "tsv"
    return "tsv"


class ZeekParser:
    """
    Parse Zeek ssl.log and conn.log files (TSV or JSON) into normalized events.
    Clusters events by (src_host, dst_host, dst_port).
    """

    def parse_file(self, path: str | Path, log_type: str | None = None) -> list[dict]:
        """
        Parse a single Zeek log file.

        Args:
            path: Path to the log file.
            log_type: 'ssl' or 'conn'. If None, inferred from filename.

        Returns:
            List of normalized event dicts.
        """
        path = Path(path)
        if log_type is None:
            name = path.stem.lower()
            if "ssl" in name:
                log_type = "ssl"
            elif "conn" in name:
                log_type = "conn"
            else:
                raise ValueError(f"Cannot infer log_type from filename: {path.name}")

        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            raw_lines = fh.readlines()

        return self.parse_lines(raw_lines, log_type)

    def parse_lines(self, lines: list[str], log_type: str) -> list[dict]:
        """Parse a list of lines in TSV or JSON format."""
        fmt = _detect_format(lines)
        if fmt == "json":
            raw_iter = _parse_json_log(iter(lines), log_type)
        else:
            raw_iter = _parse_tsv_log(iter(lines), log_type)

        events = []
        for raw in raw_iter:
            if log_type == "conn":
                ev = _normalize_conn(raw)
            else:
                ev = _normalize_ssl(raw)
            # Skip events with no timestamp or hosts
            if ev["ts"] is None or ev["src_host"] is None or ev["dst_host"] is None:
                continue
            events.append(ev)

        return events

    def parse_string(self, text: str, log_type: str) -> list[dict]:
        """Parse a Zeek log from a string."""
        return self.parse_lines(text.splitlines(keepends=True), log_type)

    def cluster(self, events: list[dict]) -> dict[tuple, list[dict]]:
        """
        Cluster events by (src_host, dst_host, dst_port).

        Returns:
            Dict mapping (src_host, dst_host, dst_port) -> sorted list of events.
        """
        clusters: dict[tuple, list[dict]] = defaultdict(list)
        for ev in events:
            key = (ev["src_host"], ev["dst_host"], ev["dst_port"])
            clusters[key].append(ev)
        # Sort each cluster by timestamp
        for key in clusters:
            clusters[key].sort(key=lambda e: e["ts"] or 0)
        return dict(clusters)
