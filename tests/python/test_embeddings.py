"""
test_embeddings.py — Regression tests for agents/shared/embeddings.py

All tests run offline: no network, no real API key required.
asyncio_mode=auto (set in pytest.ini) means plain `async def test_*` works.
"""

from __future__ import annotations

import math
import os
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path bootstrap (mirrors conftest.py but kept explicit for clarity)
# ---------------------------------------------------------------------------
_SHARED = str(Path(__file__).resolve().parents[2] / "agents" / "shared")
if _SHARED not in sys.path:
    sys.path.insert(0, _SHARED)

import embeddings  # noqa: E402  (must come after sys.path fixup)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(x * x for x in b))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


def norm(v: list[float]) -> float:
    return math.sqrt(sum(x * x for x in v))


# ---------------------------------------------------------------------------
# is_stub() detection
# ---------------------------------------------------------------------------

def test_is_stub_when_key_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("EMBED_PROVIDER", raising=False)
    # Force module to re-read env (is_stub reads os.getenv live)
    assert embeddings.is_stub() is True


def test_is_stub_when_key_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "")
    monkeypatch.delenv("EMBED_PROVIDER", raising=False)
    assert embeddings.is_stub() is True


def test_is_stub_forced_by_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "some-key")
    monkeypatch.setenv("EMBED_PROVIDER", "stub")
    assert embeddings.is_stub() is True


def test_is_stub_false_when_key_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "real-looking-key")
    monkeypatch.delenv("EMBED_PROVIDER", raising=False)
    assert embeddings.is_stub() is False


# ---------------------------------------------------------------------------
# embed() — length and dimensionality
# ---------------------------------------------------------------------------

async def test_embed_returns_correct_count(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("EMBED_PROVIDER", "stub")
    texts = ["hello world", "DNS spike detected", "suricata alert triggered"]
    result = await embeddings.embed(texts)
    assert len(result) == len(texts)


async def test_embed_returns_correct_dim(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("EMBED_PROVIDER", "stub")
    texts = ["ping sweep detected on subnet 10.0.0.0/24"]
    result = await embeddings.embed(texts)
    assert len(result[0]) == embeddings.EMBED_DIM


async def test_embed_empty_input(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("EMBED_PROVIDER", "stub")
    result = await embeddings.embed([])
    assert result == []


# ---------------------------------------------------------------------------
# L2 normalization: each vector should have norm ≈ 1.0
# ---------------------------------------------------------------------------

async def test_vectors_are_l2_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("EMBED_PROVIDER", "stub")
    texts = [
        "ET SCAN Nmap Aggressive scan",
        "DNS query to known C2 domain",
        "SSH brute-force attempt from 192.168.1.100",
        "",  # empty string edge case
        "a",  # single char
    ]
    result = await embeddings.embed(texts)
    for i, vec in enumerate(result):
        n = norm(vec)
        assert abs(n - 1.0) < 1e-5, (
            f"Vector {i} (text={texts[i]!r}) has norm {n}, expected ~1.0"
        )


# ---------------------------------------------------------------------------
# Determinism: same text → identical vector across two calls
# ---------------------------------------------------------------------------

async def test_stub_is_deterministic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("EMBED_PROVIDER", "stub")
    texts = ["zeek notice: SSH::Password_Guessing", "suricata ET SCAN"]
    first = await embeddings.embed(texts)
    second = await embeddings.embed(texts)
    for i, (a, b) in enumerate(zip(first, second)):
        assert a == b, f"Vector {i} is not deterministic across two calls"


# ---------------------------------------------------------------------------
# Semantic ordering: near-identical text shares more n-grams than unrelated
# ---------------------------------------------------------------------------

async def test_cosine_ordering(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    anchor  = "DNS query to known C2 domain"
    similar = "DNS query to known C2 domain type A"  (one token appended)
    unrelated = "Physical breach detected at server room"

    Expected: cosine(anchor, similar) > cosine(anchor, unrelated)
    """
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("EMBED_PROVIDER", "stub")

    anchor = "DNS query to known C2 domain"
    similar = "DNS query to known C2 domain type A"
    unrelated = "Physical breach detected at server room door"

    vecs = await embeddings.embed([anchor, similar, unrelated])
    v_anchor, v_similar, v_unrelated = vecs

    sim_close = cosine(v_anchor, v_similar)
    sim_far = cosine(v_anchor, v_unrelated)

    assert sim_close > sim_far, (
        f"Expected cosine(anchor, similar)={sim_close:.4f} > "
        f"cosine(anchor, unrelated)={sim_far:.4f}"
    )


async def test_different_texts_produce_different_vectors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("EMBED_PROVIDER", "stub")
    vecs = await embeddings.embed(["hello security world", "completely unrelated topic x"])
    assert vecs[0] != vecs[1]


# ---------------------------------------------------------------------------
# EMBED_DIM constant sanity
# ---------------------------------------------------------------------------

def test_embed_dim_constant() -> None:
    assert embeddings.EMBED_DIM == 768


# ---------------------------------------------------------------------------
# Lazy import: importing embeddings with no key doesn't blow up even if
# langchain_google_genai is not installed
# ---------------------------------------------------------------------------

def test_module_importable_without_cloud_deps(monkeypatch: pytest.MonkeyPatch) -> None:
    """The module must be importable (and stub path usable) without langchain_google_genai."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("EMBED_PROVIDER", "stub")
    # If we got here the import at top-of-file already succeeded. Just confirm
    # the stub path works without any cloud package.
    import importlib
    mod = importlib.import_module("embeddings")
    assert hasattr(mod, "embed")
    assert hasattr(mod, "is_stub")
    assert hasattr(mod, "EMBED_DIM")
