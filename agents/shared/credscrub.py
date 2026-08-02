"""Canonical credential scrubbing for text that reaches a user's browser.

Companion to ipscope: that module decides which ADDRESSES may be displayed, this
one strips CREDENTIALS. Import from here rather than re-deriving the patterns —
five copies of an IP regex is how the leaked-octet bug survived so long.

The hash carve-out is the subtle part. A naive "40+ base64-ish chars" rule eats
MD5/SHA-1/SHA-256 file hashes, which are exactly the IOCs a SOC analyst needs to
see. The negative lookahead skips tokens that are ENTIRELY hex; a real base64
secret contains at least one non-hex character and is still caught.
"""

from __future__ import annotations

import re

__all__ = ["scrub_secrets"]

# Entirely-hex tokens are hashes (MD5=32, SHA-1=40, SHA-256=64) and must survive.
_RE_SECRET_TOKEN = re.compile(r"\b(?![A-Fa-f0-9]{40,}\b)[A-Za-z0-9+/]{40,}\b")
_RE_PASSWORD = re.compile(r"(?i)password\s*[:=]\s*\S+")
_RE_API_KEY = re.compile(r"(?i)api[_-]?key\s*[:=]\s*\S+")
# JSON-quoted form. `password=x` was covered but `"password":"x"` was not, and query
# results reach the LLM as json.dumps of Athena rows — the one shape that actually
# occurs. Both `ftp` and `http` carry a real `password` column on this network, so a
# credential the sensor captured could egress verbatim. Keyed on the quoted name so a
# value containing ':' or a space still matches to its closing quote.
_RE_JSON_SECRET = re.compile(
    r'(?i)"(password|passwd|pwd|secret|api[_-]?key|token|authorization)"\s*:\s*"[^"]*"'
)
_RE_BEARER = re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+")
# Provider-prefixed keys, which are shorter than the generic 40-char rule.
_RE_PREFIXED_KEY = re.compile(r"\b(?:sk|pk|rk|xoxb|xoxp|ghp|gho|AKIA)[-_A-Za-z0-9]{12,}\b")
_RE_AWS_SECRET = re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*\S+")


def scrub_secrets(text: str) -> str:
    """Strip credentials from free text. Safe on non-strings and empty input."""
    if not isinstance(text, str) or not text:
        return text
    text = _RE_AWS_SECRET.sub("aws_secret_access_key: [REDACTED]", text)
    # Before the bare-word rules: those would eat the opening quote and leave the
    # value's closing quote behind, producing invalid JSON the model then misreads.
    text = _RE_JSON_SECRET.sub(lambda m: f'"{m.group(1)}":"[REDACTED]"', text)
    text = _RE_PASSWORD.sub("password: [REDACTED]", text)
    text = _RE_API_KEY.sub("api_key: [REDACTED]", text)
    text = _RE_BEARER.sub("bearer [REDACTED]", text)
    text = _RE_PREFIXED_KEY.sub("[REDACTED-SECRET]", text)
    text = _RE_SECRET_TOKEN.sub("[REDACTED-SECRET]", text)
    return text
