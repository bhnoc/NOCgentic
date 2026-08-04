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
_RE_PREFIXED_KEY = re.compile(r"\b(?:sk|pk|rk|xoxb|xoxp|ghp|gho|AKIA|AIza)[-_A-Za-z0-9]{12,}\b")

# PEM private keys. Found reaching Manifold AND the permanent S3 span archive in
# the clear on 2026-08-04: no rule matched them. The body is base64 and long, so
# _RE_SECRET_TOKEN eats most interior lines, but the ARMOUR survives and the
# first/last lines can be short enough to slip through -- leaving something that
# still reads as a key. Match the whole block, header to footer, and drop it.
# DOTALL because a real key is multi-line; non-greedy so two keys in one blob do
# not collapse into one match with the text between them swallowed.
_RE_PRIVATE_KEY = re.compile(
    r"-----BEGIN[A-Z ]*PRIVATE KEY-----.*?-----END[A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
# An unterminated header still means a key was pasted; catch it on its own.
_RE_PRIVATE_KEY_HEADER = re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----")

# OIDC / client-credentials secrets. MANIFOLD_OIDC_SECRET is the credential that
# can rewrite our own detection policies, and no existing rule matched it:
# _RE_API_KEY only fires on the literal "api_key", and the value is short enough
# to miss the 40-char token rule.
_RE_OIDC_SECRET = re.compile(
    r"(?i)\b(?:[a-z0-9_]*(?:client|oidc)_secret|manifold_oidc_(?:id|secret))\s*[:=]\s*\S+"
)
_RE_AWS_SECRET = re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*\S+")


def scrub_secrets(text: str) -> str:
    """Strip credentials from free text. Safe on non-strings and empty input."""
    if not isinstance(text, str) or not text:
        return text
    # Private keys FIRST. The body is base64, so any later rule would chew it
    # into fragments and leave the armour behind, which still discloses that a
    # key was present and where it started.
    text = _RE_PRIVATE_KEY.sub("[REDACTED-PRIVATE-KEY]", text)
    text = _RE_PRIVATE_KEY_HEADER.sub("[REDACTED-PRIVATE-KEY]", text)
    text = _RE_OIDC_SECRET.sub("oidc_secret: [REDACTED]", text)
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
