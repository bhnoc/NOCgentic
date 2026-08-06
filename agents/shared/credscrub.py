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
# Charset covers both base64 alphabets: standard (+/) AND URL-safe (-_), the
# latter used by JWTs and most query-string auth tokens (e.g. Google's
# cup2key=). A screenshot review 2026-08-05 found tokens like
# "yasFogI_fTvL5ud6bn7fKbyLWBLnuTSwtlhfJCSql-c" reaching the browser intact —
# the standard-only charset splits on every '-'/'_', so no fragment ever hit
# the 40-char floor. Hyphenated hostnames/domains don't false-trigger: '.'
# still breaks the run, so "a-very-long-subdomain.example.com" is untouched.
_RE_SECRET_TOKEN = re.compile(r"\b(?![A-Fa-f0-9]{40,}\b)[A-Za-z0-9+/\-_]{40,}\b")
_RE_PASSWORD = re.compile(r"(?i)password\s*[:=]\s*\S+")
_RE_API_KEY = re.compile(r"(?i)api[_-]?key\s*[:=]\s*\S+")
# JSON-quoted form. `password=x` was covered but `"password":"x"` was not, and query
# results reach the LLM as json.dumps of Athena rows — the one shape that actually
# occurs. Both `ftp` and `http` carry a real `password` column on this network, so a
# credential the sensor captured could egress verbatim. Keyed on the quoted name so a
# value containing ':' or a space still matches to its closing quote.
#
# The value group must skip escaped quotes (\") as well as plain non-quote
# characters, or a value containing one — plausible for anything that is
# itself JSON-in-JSON, or just a password containing a literal '"' — stops the
# match at the escape and leaves the real closing quote plus everything after
# it (the actual secret tail) sitting in the output right after [REDACTED].
#
# Non-greedy (*?) plus a lookahead requiring the closing quote be followed by
# a comma or brace (the only two things a real JSON encoder ever emits after a
# field value): malformed/naive-string-concat input can carry a lone,
# UNescaped backslash immediately before what should be the closing quote
# (`"password":"abc\","token":"REALSECRET"`, e.g. a password containing a
# backslash that never went through a real JSON encoder). A greedy `\\.`
# reads that `\"` as an escaped quote and keeps consuming into the NEXT
# field's opening quote, so the substitution swallows `"token` whole and
# leaves the real secret value completely unquoted and un-redacted right
# after it. The lookahead stops the match at the first quote that actually
# looks like end-of-value, so the next field starts clean and still matches
# on its own.
_RE_JSON_SECRET = re.compile(
    r'(?i)"(password|passwd|pwd|secret|api[_-]?key|token|authorization)"\s*:\s*"(?:\\.|[^"\\])*?"(?=\s*[,}])'
)
# JWTs are dot-separated URL-safe base64 (covered by the bare charset), but
# opaque bearer tokens from other providers (OAuth access tokens, some vendor
# APIs) use STANDARD base64 with '+', '/', and '=' padding. Without those in
# the charset, "Bearer AAAB3NzaC1y+ccKV/==" redacted only up to the '+' and
# left "ccKV/==" exposed right after "bearer [REDACTED]".
_RE_BEARER = re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-+/=]+")
# Provider-prefixed keys, which are shorter than the generic 40-char rule.
# Not exhaustive by construction (a bare prefix list never is), but covers
# every vendor with a fixed literal prefix we know of: Stripe (sk_live_/
# sk_test_/rk_live_), the full Slack token family (not just bot/user tokens),
# GitHub's fine-grained PAT plus the app/refresh/user-to-server tokens (only
# ghp_/gho_ were covered before), and Anthropic's own key format.
_RE_PREFIXED_KEY = re.compile(
    r"\b(?:sk|pk|rk|sk_live|sk_test|rk_live|xoxb|xoxp|xoxa|xoxr|xoxs|"
    r"ghp|gho|ghu|ghs|ghr|github_pat|sk-ant|AKIA|AIza)[-_A-Za-z0-9]{12,}\b"
)

# PEM private keys. Found reaching Manifold AND the permanent S3 span archive in
# the clear on 2026-08-04: no rule matched them. The body is base64 and long, so
# _RE_SECRET_TOKEN eats most interior lines, but the ARMOUR survives and the
# first/last lines can be short enough to slip through -- leaving something that
# still reads as a key. Match the whole block, header to footer, and drop it.
# DOTALL because a real key is multi-line; non-greedy so two keys in one blob do
# not collapse into one match with the text between them swallowed.
#
# "[A-Z ]*" alone matches RSA/EC/DSA/OPENSSH PEM headers (-----BEGIN RSA
# PRIVATE KEY-----) but not PGP's real export shape, which has a trailing
# " BLOCK" between "KEY" and the closing dashes (-----BEGIN PGP PRIVATE KEY
# BLOCK-----). That word sat outside both the opening and closing anchors, so
# a pasted PGP private key matched neither this rule nor the header fallback
# and rendered in full. "\s+BLOCK)?" makes the BLOCK suffix optional so both
# shapes match with one pattern.
_RE_PRIVATE_KEY = re.compile(
    r"-----BEGIN[A-Z ]*PRIVATE KEY(?:\s+BLOCK)?-----.*?-----END[A-Z ]*PRIVATE KEY(?:\s+BLOCK)?-----",
    re.DOTALL,
)
# An unterminated header still means a key was pasted; catch it on its own.
_RE_PRIVATE_KEY_HEADER = re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY(?:\s+BLOCK)?-----")

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
