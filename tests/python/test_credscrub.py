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
