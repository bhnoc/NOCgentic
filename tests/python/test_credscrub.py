"""Gate for credential scrubbing on browser-facing text.

QA sweep finding: sanitize_output_text() (the user-facing egress sanitizer)
redacted IPs and zone names but never applied the credential patterns that the
LLM-input sanitize() used, so a key quoted in an agent error message reached the
browser intact.

Second requirement, easy to break: the scrubber must NOT eat file hashes. A naive
"40+ base64-ish chars" rule destroys MD5/SHA-1/SHA-256 IOCs, which are exactly
what a SOC analyst needs to see.
"""

import os
import json
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "agents", "shared"))

from credscrub import scrub_secrets  # noqa: E402

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
MD5 = "d41d8cd98f00b204e9800998ecf8427e"


class TestCredentialsRemoved:
    @pytest.mark.parametrize(
        "text,leak",
        [
            ("api_key=SUPERSECRETVALUE123", "SUPERSECRETVALUE123"),
            ("api-key: abcdefghijklmnop", "abcdefghijklmnop"),
            ("password: hunter2", "hunter2"),
            ("PASSWORD=CorrectHorseBattery", "CorrectHorseBattery"),
            ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc", "eyJhbGciOiJIUzI1NiJ9"),
            ("aws_secret_access_key=wJalrXUtnFEMI0K7MDENGbPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI"),
            ("key sk-proj-AbCdEf1234567890GhIjKlMn", "sk-proj-AbCdEf1234567890GhIjKlMn"),
            ("token AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
        ],
    )
    def test_secret_is_removed(self, text, leak):
        assert leak not in scrub_secrets(text)

    def test_long_base64_token_removed(self):
        token = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbg=="
        assert token.rstrip("=") not in scrub_secrets(f"blob {token}")


class TestHashIOCsSurvive:
    """Destroying IOCs would be a worse defect than the leak it prevents."""

    @pytest.mark.parametrize("h", [SHA256, SHA1, MD5])
    def test_hash_is_preserved(self, h):
        assert h in scrub_secrets(f"file hash {h} seen on host")

    def test_hash_survives_alongside_a_secret(self):
        out = scrub_secrets(f"hash={SHA256} api_key=LEAKMENOT123456")
        assert SHA256 in out
        assert "LEAKMENOT123456" not in out


class TestSafety:
    def test_non_strings_and_empty(self):
        assert scrub_secrets("") == ""
        assert scrub_secrets(None) is None
        assert scrub_secrets(42) == 42

    def test_ordinary_text_untouched(self):
        text = "Port scan from 10.220.40.7 to 45.83.193.150 on TCP/4444"
        assert scrub_secrets(text) == text


class TestUserFacingEgressAppliesIt:
    """The whole point: the browser-facing sanitizer must scrub credentials."""

    def test_orchestrator_output_sanitizer_strips_secrets(self):
        pytest.importorskip("fastapi")
        import importlib.util

        path = os.path.join(
            os.path.dirname(__file__), "..", "..", "agents", "orchestrator", "main.py"
        )
        spec = importlib.util.spec_from_file_location("orch_main", path)
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as exc:
            pytest.skip(f"orchestrator deps unavailable: {exc}")

        out = module.sanitize_output_text(
            "query failed: api_key=LEAKEDKEYVALUE99 password: hunter2 host 10.0.1.63"
        )
        assert "LEAKEDKEYVALUE99" not in out
        assert "hunter2" not in out
        assert "10.0.1.63" not in out


class TestTelemetryUsesTheSharedScrubber:
    """Debt sweep: telemetry.py carried its own copy of the secret patterns and
    drifted. credscrub grew provider-prefixed-key and aws_secret rules that the
    copy never got, so AKIA/sk- keys reached the OTLP endpoint and the permanent
    S3 trace archive unredacted. Lock the two paths together."""

    @pytest.mark.parametrize(
        "text,leak",
        [
            ("token AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
            ("key sk-proj-AbCdEf1234567890GhIjKlMn", "sk-proj-AbCdEf1234567890GhIjKlMn"),
            ("aws_secret_access_key=wJalrXUtnFEMI0K7MDENGbPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI"),
            ("password: hunter2", "hunter2"),
            ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc", "eyJhbGciOiJIUzI1NiJ9"),
        ],
    )
    def test_telemetry_redaction_matches_credscrub(self, text, leak):
        import telemetry
        assert leak not in telemetry._redact(text), "telemetry redaction drifted from credscrub"

    def test_telemetry_still_preserves_hash_iocs(self):
        import telemetry
        assert SHA256 in telemetry._redact(f"file {SHA256} seen")

    def test_telemetry_has_no_local_secret_patterns(self):
        """A reintroduced local copy is how this drifted the first time."""
        import inspect

        import telemetry
        src = inspect.getsource(telemetry)
        for name in ("_RE_SECRET_TOKEN", "_RE_PASSWORD", "_RE_API_KEY", "_RE_BEARER"):
            assert name not in src, f"{name} is back in telemetry.py; use credscrub"


class TestJsonShapedSecrets:
    """Athena rows reach the LLM as json.dumps output, so the JSON-quoted form is
    the shape that actually occurs in production -- and it was the one shape not
    covered. `password=x` matched; `"password":"x"` did not.

    This is not hypothetical: both `ftp` and `http` carry a real `password` column
    in this catalog, so a credential the sensor captured off the wire could reach
    an external LLM verbatim (LLM_PROVIDER=gemini in prod).
    """

    @pytest.mark.parametrize("key", [
        "password", "passwd", "pwd", "secret", "api_key", "api-key", "apikey",
        "token", "authorization",
    ])
    def test_json_quoted_secret_is_redacted(self, key):
        payload = '{"id_orig_h":"10.220.31.5","%s":"s3kr3t-value"}' % key
        assert "s3kr3t-value" not in scrub_secrets(payload)

    def test_case_insensitive(self):
        assert "s3kr3t" not in scrub_secrets('{"PassWord":"s3kr3t"}')

    def test_value_containing_a_colon_or_space_is_fully_redacted(self):
        """A bare-word rule stops at whitespace, so a value with a space used to
        leak its tail. Anchoring on the closing quote covers the whole value."""
        out = scrub_secrets('{"password":"two words: and a colon"}')
        for leak in ("two words", "and a colon"):
            assert leak not in out

    def test_output_is_still_parseable_json(self):
        """The redaction must not eat a quote. Invalid JSON is worse than a
        redacted value: the model silently misreads the remaining fields."""
        rows = [{"id_orig_h": "10.220.31.5", "user_": "svc", "password": "p"}]
        out = scrub_secrets(json.dumps(rows))
        assert json.loads(out)[0]["password"] == "[REDACTED]"
        assert json.loads(out)[0]["user_"] == "svc", "a non-secret field was damaged"

    def test_hash_iocs_still_survive_in_json(self):
        """The entire reason this module exists: an MD5/SHA is evidence, not a
        secret, and redacting it destroys the analyst's pivot."""
        payload = '{"md5":"%s","sha256":"%s"}' % (MD5, SHA256)
        out = scrub_secrets(payload)
        assert MD5 in out and SHA256 in out

    def test_a_username_is_not_treated_as_a_secret(self):
        """user_ is identity, not a credential, and the analyst needs it."""
        out = scrub_secrets('{"user_":"alice","password":"x"}')
        assert "alice" in out


# ---------------------------------------------------------------------------
# Gaps found 2026-08-04 by pushing the Manifold policy test vectors through the
# REAL export redactor: these three credential forms reached Manifold AND the
# permanent S3 span archive in the clear, because no pattern matched them.
# ---------------------------------------------------------------------------

class TestExportGapsFound20260804:
    def test_pem_private_key_block_is_removed_entirely(self):
        text = (
            "here is the key\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEAx7Wn3kQm2p\n"
            "9s0dFakeKeyMaterialHere1234\n"
            "-----END RSA PRIVATE KEY-----\n"
            "and that was it"
        )
        out = scrub_secrets(text)
        assert "BEGIN RSA PRIVATE KEY" not in out
        assert "MIIEowIBAAKCAQEAx7Wn3kQm2p" not in out
        assert "[REDACTED-PRIVATE-KEY]" in out
        # surrounding prose must survive — this runs on analyst-facing text
        assert "here is the key" in out and "and that was it" in out

    def test_openssh_and_ec_key_headers_also_match(self):
        for kind in ("OPENSSH", "EC", "DSA", ""):
            header = f"-----BEGIN {kind} PRIVATE KEY-----".replace("  ", " ")
            out = scrub_secrets(f"leak: {header} body")
            assert "PRIVATE KEY" not in out, kind

    def test_unterminated_header_still_redacted(self):
        # A truncated paste is still a disclosure that a key was present.
        out = scrub_secrets("-----BEGIN PRIVATE KEY----- MIIEow")
        assert "BEGIN" not in out

    def test_two_keys_do_not_collapse_into_one_match(self):
        # Non-greedy: the text BETWEEN two keys must not be swallowed.
        text = ("-----BEGIN PRIVATE KEY-----\naaa\n-----END PRIVATE KEY-----"
                " KEEP-THIS "
                "-----BEGIN PRIVATE KEY-----\nbbb\n-----END PRIVATE KEY-----")
        out = scrub_secrets(text)
        assert "KEEP-THIS" in out
        assert "aaa" not in out and "bbb" not in out

    def test_google_api_key_is_redacted(self):
        out = scrub_secrets("key AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q")
        assert "AIzaSy" not in out

    def test_manifold_oidc_secret_is_redacted(self):
        for line in ("MANIFOLD_OIDC_SECRET=s3cret-value-here",
                     "MANIFOLD_OIDC_ID: abc123",
                     "client_secret = hunter2hunter2",
                     "OIDC_SECRET:zzz"):
            out = scrub_secrets(line)
            assert "s3cret-value-here" not in out
            assert "abc123" not in out
            assert "hunter2hunter2" not in out
            assert "zzz" not in out

    def test_file_hashes_still_survive(self):
        # THE carve-out this module exists for: hashes are the IOCs an analyst
        # needs to see. The new rules must not regress it.
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        out = scrub_secrets(f"hashes {sha256} and {md5}")
        assert sha256 in out and md5 in out

    def test_ordinary_prose_untouched(self):
        text = "The Registration zone had 4.2 GB of egress and no private key material."
        assert scrub_secrets(text) == text
