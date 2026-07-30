"""
test_templating.py — Tests for agents/shared/templating.py

Covers:
- premask token replacement (IPv4, IPv4:port, UID, MAC, sha256 hex, large ints, domains)
- Determinism (same input -> identical output on repeated calls)
- 100 lines with different src IPs/ports collapse to ONE template
- Two genuinely different signatures -> two templates
- match() is non-mutating (no cluster growth)
"""

from __future__ import annotations

import sys
import os
import random
import string

# Make agents/shared importable without an installed package.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "agents", "shared"))

from templating import premask, TemplateMiner, EMBED_MASK_TOKENS  # noqa: E402

# ---------------------------------------------------------------------------
# Fixture data
# ---------------------------------------------------------------------------

# A realistic Corelight/Zeek + Suricata-style alert line.
# Placeholders {src_ip}, {src_port} are filled per test.
_SURICATA_TMPL = (
    "ts=2026-07-30T10:00:01Z "
    "uid={uid} "
    "id.orig_h={src_ip} id.orig_p={src_port} "
    "id.resp_h=185.220.101.7 id.resp_p=443 "
    'alert.signature="ET MALWARE Cobalt Strike Beacon" severity=1'
)

# Zeek dns.log — structurally distinct from the Suricata alert above:
# different field names (query, qtype_name, rcode_name, answers) vs
# (id.resp_h, id.resp_p, alert.signature, severity).
_SURICATA_TMPL2 = (
    "ts=2026-07-30T10:00:02Z "
    "uid={uid} "
    "id.orig_h={src_ip} id.orig_p={src_port} "
    "id.resp_h=8.8.8.8 id.resp_p=53 "
    "query=evil.example.com qtype_name=A rcode_name=NOERROR "
    "answers=185.220.101.7"
)

SHA256 = "a" * 64  # 64-char hex string


def _rand_uid() -> str:
    """Generate a random Zeek-style UID: C + 15 base62 chars."""
    chars = string.ascii_letters + string.digits
    return "C" + "".join(random.choices(chars, k=15))


def _rand_ip() -> str:
    return f"10.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"


def _rand_port() -> int:
    return random.randint(49152, 65535)


# ---------------------------------------------------------------------------
# premask — unit tests
# ---------------------------------------------------------------------------


class TestPremask:
    def test_ipv4_masked(self):
        masked, params = premask("connect from 192.168.1.100 to 10.0.0.1")
        assert "192.168.1.100" not in masked
        assert "10.0.0.1" not in masked
        assert "<IP>" in masked
        assert "192.168.1.100" in params["<IP>"]
        assert "10.0.0.1" in params["<IP>"]

    def test_ipv4_port_masked(self):
        masked, params = premask("src=10.220.5.13:51344 dst=185.220.101.7:443")
        assert "10.220.5.13" not in masked
        assert "51344" not in masked
        assert "<IP>:<PORT>" in masked
        assert "10.220.5.13" in params["<IP>"]
        assert "51344" in params["<PORT>"]
        assert "443" in params["<PORT>"]

    def test_uid_masked(self):
        uid = "CwXvZ2abcDEfghIJ0"  # C + 16 chars = valid Zeek UID
        masked, params = premask(f"uid={uid} proto=tcp")
        assert uid not in masked
        assert "<UID>" in masked
        assert uid in params["<UID>"]

    def test_mac_masked(self):
        masked, params = premask("src_mac=00:1a:2b:3c:4d:5e dst_mac=AA-BB-CC-DD-EE-FF")
        assert "00:1a:2b:3c:4d:5e" not in masked
        assert "<MAC>" in masked
        assert "00:1a:2b:3c:4d:5e" in params["<MAC>"]

    def test_sha256_hex_masked(self):
        masked, params = premask(f"hash={SHA256} status=ok")
        assert SHA256 not in masked
        assert "<HEX>" in masked
        assert SHA256 in params["<HEX>"]

    def test_large_int_masked(self):
        masked, params = premask("bytes=123456 count=999")
        assert "123456" not in masked
        assert "999" not in masked
        assert "<NUM>" in masked
        assert "123456" in params["<NUM>"]
        assert "999" in params["<NUM>"]

    def test_small_int_not_masked(self):
        """Integers < 3 digits should NOT be masked."""
        masked, _ = premask("severity=1 version=2 retry=99")
        assert "1" in masked
        assert "2" in masked
        assert "99" in masked

    def test_domain_masked(self):
        masked, params = premask("query=evil.example.com rcode=NOERROR")
        assert "evil.example.com" not in masked
        assert "<DOMAIN>" in masked
        assert "evil.example.com" in params["<DOMAIN>"]

    def test_timestamp_masked(self):
        masked, params = premask("ts=2026-07-30T10:00:01Z action=login")
        assert "2026-07-30T10:00:01Z" not in masked
        assert "<TS>" in masked

    def test_determinism(self):
        """Same input must produce identical output on two consecutive calls."""
        line = (
            "ts=2026-07-30T10:00:01Z uid=CwXvZ2abcDEfghIJ0 "
            "src=10.220.5.13:51344 dst=185.220.101.7:443 "
            f"hash={SHA256} bytes=98765 domain=evil.example.com"
        )
        m1, p1 = premask(line)
        m2, p2 = premask(line)
        assert m1 == m2
        assert p1 == p2

    def test_embed_mask_tokens_constant(self):
        """EMBED_MASK_TOKENS must contain all placeholder types."""
        expected = {"<IP>", "<UID>", "<PORT>", "<HEX>", "<NUM>", "<TS>", "<MAC>", "<DOMAIN>"}
        assert expected == EMBED_MASK_TOKENS


# ---------------------------------------------------------------------------
# TemplateMiner — collapse tests
# ---------------------------------------------------------------------------


class TestTemplateMiner:
    def test_100_identical_structure_one_template(self):
        """100 lines with different src IPs/ports must collapse to exactly ONE template."""
        miner = TemplateMiner()
        for i in range(100):
            line = _SURICATA_TMPL.format(
                uid=_rand_uid(),
                src_ip=_rand_ip(),
                src_port=_rand_port(),
            )
            miner.add(line)

        tmpl_list = miner.templates()
        assert len(tmpl_list) == 1, (
            f"Expected 1 template, got {len(tmpl_list)}: {tmpl_list}"
        )
        assert tmpl_list[0]["cluster_size"] == 100

    def test_two_signatures_two_templates(self):
        """Two genuinely different alert signatures must produce two templates."""
        miner = TemplateMiner()
        for i in range(10):
            miner.add(
                _SURICATA_TMPL.format(
                    uid=_rand_uid(), src_ip=_rand_ip(), src_port=_rand_port()
                )
            )
            miner.add(
                _SURICATA_TMPL2.format(
                    uid=_rand_uid(), src_ip=_rand_ip(), src_port=_rand_port()
                )
            )

        tmpl_list = miner.templates()
        assert len(tmpl_list) == 2, (
            f"Expected 2 templates, got {len(tmpl_list)}: "
            f"{[t['template'] for t in tmpl_list]}"
        )

    def test_add_return_shape(self):
        """add() must return the documented dict shape with expected keys."""
        miner = TemplateMiner()
        line = _SURICATA_TMPL.format(
            uid=_rand_uid(), src_ip="10.0.0.1", src_port=54321
        )
        result = miner.add(line)
        assert set(result.keys()) == {"template_id", "template", "cluster_size", "params"}
        assert isinstance(result["template_id"], str)
        assert isinstance(result["template"], str)
        assert isinstance(result["cluster_size"], int)
        assert isinstance(result["params"], dict)

    def test_template_id_stable(self):
        """The same structural template must always return the same template_id."""
        miner = TemplateMiner()
        r1 = miner.add(
            _SURICATA_TMPL.format(uid=_rand_uid(), src_ip="10.1.1.1", src_port=10001)
        )
        r2 = miner.add(
            _SURICATA_TMPL.format(uid=_rand_uid(), src_ip="10.2.2.2", src_port=10002)
        )
        assert r1["template_id"] == r2["template_id"]

    def test_match_is_non_mutating(self):
        """match() must not create or grow clusters."""
        miner = TemplateMiner()

        # Prime with one line so there's a cluster to match against.
        line = _SURICATA_TMPL.format(
            uid=_rand_uid(), src_ip="10.10.10.10", src_port=55000
        )
        miner.add(line)

        before = miner.templates()
        assert len(before) == 1
        before_size = before[0]["cluster_size"]

        # match() with a structurally identical line.
        new_line = _SURICATA_TMPL.format(
            uid=_rand_uid(), src_ip="10.20.20.20", src_port=56000
        )
        result = miner.match(new_line)

        after = miner.templates()
        assert len(after) == 1, "match() must not create new templates"
        assert after[0]["cluster_size"] == before_size, (
            "match() must not grow cluster_size"
        )
        assert result is not None
        assert result["template_id"] == before[0]["template_id"]

    def test_match_returns_none_for_unknown(self):
        """match() returns None when no template has been seen yet."""
        miner = TemplateMiner()
        result = miner.match("completely unknown log line")
        assert result is None

    def test_match_returns_none_no_side_effects(self):
        """match() on empty miner leaves templates() empty."""
        miner = TemplateMiner()
        miner.match("no templates exist yet 12345")
        assert miner.templates() == []

    def test_params_contain_original_values(self):
        """add() params dict must record the actual IP/port from the line."""
        miner = TemplateMiner()
        line = _SURICATA_TMPL.format(
            uid="CwXvZ2abcDEfghIJ0",
            src_ip="10.220.5.13",
            src_port=51344,
        )
        result = miner.add(line)
        params = result["params"]
        # The src ip:port should be captured
        assert "10.220.5.13" in params.get("<IP>", []) or (
            # might be captured as IPv4:port pair
            "10.220.5.13" in params.get("<IP>", [])
        )

    def test_ip_masked_out_of_template(self):
        """The cluster template must not contain a raw IP address."""
        miner = TemplateMiner()
        for i in range(5):
            miner.add(
                _SURICATA_TMPL.format(
                    uid=_rand_uid(), src_ip=_rand_ip(), src_port=_rand_port()
                )
            )
        for tmpl in miner.templates():
            # No raw IPv4-looking token should survive in the template string.
            import re
            assert not re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", tmpl["template"]), (
                f"Raw IP found in template: {tmpl['template']}"
            )
