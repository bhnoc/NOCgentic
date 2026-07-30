"""
embeddings.py — Pluggable async embeddings module.

Interface
---------
    EMBED_DIM = 768   # Gemini text-embedding-004 dimensionality

    def is_stub() -> bool
        True when GEMINI_API_KEY is absent/empty OR EMBED_PROVIDER=stub is set.

    async def embed(texts: list[str]) -> list[list[float]]
        Returns one L2-normalized 768-float vector per input text.

        Real path  : GoogleGenerativeAIEmbeddings(model="models/text-embedding-004")
                     imported LAZILY (so importing this module never needs the package).
                     On any exception, logs a warning and falls back to the stub.

        Stub path  : Deterministic hashed char 3-gram → 768-dim vector, L2-normalized.
                     Same text → same vector. Similar text → higher cosine than unrelated.
                     No network, no randomness.

Environment variables (match llm_client.py conventions)
--------------------------------------------------------
    GEMINI_API_KEY    Google API key — absent/empty triggers stub.
    EMBED_PROVIDER    "stub" forces stub regardless of key presence.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EMBED_DIM: int = 768

# ---------------------------------------------------------------------------
# Provider detection  (mirrors llm_client.py env-var conventions)
# ---------------------------------------------------------------------------

def is_stub() -> bool:
    """Return True when we will use the deterministic offline embedder.

    Stub is forced when:
      * EMBED_PROVIDER env var is set to "stub" (case-insensitive), OR
      * GEMINI_API_KEY is absent or empty.
    """
    if os.getenv("EMBED_PROVIDER", "").lower() == "stub":
        return True
    return not bool(os.getenv("GEMINI_API_KEY", "").strip())


# ---------------------------------------------------------------------------
# Normalization helpers — pure Python, no numpy required
# ---------------------------------------------------------------------------

def _l2_norm_pure(vec: list[float]) -> list[float]:
    """L2-normalize a vector in pure Python."""
    mag = math.sqrt(sum(x * x for x in vec))
    if mag == 0.0:
        # Shouldn't happen with n-gram hashing but guard anyway.
        return vec[:]
    inv = 1.0 / mag
    return [x * inv for x in vec]


def _l2_norm(vec: list[float]) -> list[float]:
    """L2-normalize, using numpy if importable, else pure Python."""
    try:
        import numpy as np  # optional fast path
        arr = np.array(vec, dtype=np.float64)
        mag = float(np.linalg.norm(arr))
        if mag == 0.0:
            return vec[:]
        return (arr / mag).tolist()
    except ImportError:
        return _l2_norm_pure(vec)


# ---------------------------------------------------------------------------
# Stub embedder — deterministic hashed char n-gram bucketing
# ---------------------------------------------------------------------------

def _stub_embed_one(text: str) -> list[float]:
    """Produce a deterministic 768-dim L2-normalized vector from `text`.

    Algorithm:
      1. Extract all overlapping character 3-grams from the text (with
         padding so short strings still produce varied vectors).
      2. For each 3-gram, compute SHA-256 and take the first 8 bytes as a
         uint64, then bucket into [0, EMBED_DIM).
      3. Accumulate a float count in each bucket.
      4. L2-normalize the result.

    Properties:
      * Deterministic: same text → same vector, always.
      * Discriminative: different texts → different buckets activated.
      * Semantic-ish: texts sharing many 3-grams have higher cosine similarity
        than unrelated texts, because they hit more of the same buckets.
    """
    # Pad to ensure at least one 3-gram even for very short strings.
    padded = f"\x00{text}\x00"
    buckets: list[float] = [0.0] * EMBED_DIM

    n = len(padded)
    for i in range(n - 2):
        gram = padded[i : i + 3]
        digest = hashlib.sha256(gram.encode("utf-8", errors="replace")).digest()
        # First 8 bytes → uint64 (big-endian)
        idx = int.from_bytes(digest[:8], "big") % EMBED_DIM
        buckets[idx] += 1.0

    # Fallback: if text is empty after padding only produced zeros, seed one bucket.
    if all(b == 0.0 for b in buckets):
        buckets[0] = 1.0

    return _l2_norm(buckets)


async def _embed_stub(texts: list[str]) -> list[list[float]]:
    return [_stub_embed_one(t) for t in texts]


# ---------------------------------------------------------------------------
# Real embedder — GoogleGenerativeAIEmbeddings via langchain_google_genai
#   LAZY import: the package is only needed when this path is actually called.
# ---------------------------------------------------------------------------

def _is_auth_error(exc: Exception) -> bool:
    """Return True if the exception looks like an auth/config failure.

    Auth errors (bad key, 401, 403, permission denied) must NOT silently fall
    back to stub vectors — that would mix embedding spaces and corrupt the
    vector store. They are raised so the caller surfaces the root cause.

    Transient errors (timeout, rate-limit, 5xx, import errors when the package
    is temporarily unavailable, InvalidArgument for oversized/malformed input)
    may fall back with a loud WARNING.

    Classification rules (s2-05):
      * Exception TYPE name matches PermissionDenied, Unauthenticated, or
        AuthenticationError → always auth.
      * Exception TYPE name is InvalidArgument → auth ONLY if the message
        contains an api-key phrase; otherwise treat as transient/payload error
        and fall back to stub.
      * HTTP status 401/403 or keywords unauthorized/invalid api key/
        api key not valid/api_key_invalid in the message → auth.
    """
    exc_cls = type(exc).__name__
    exc_cls_lower = exc_cls.lower()
    exc_str = str(exc).lower()

    # --- Type-name based auth signals (most precise) ---
    type_auth_names = {"permissiondenied", "unauthenticated", "authenticationerror"}
    if exc_cls_lower in type_auth_names:
        return True

    # --- InvalidArgument: auth ONLY if the message specifically references an API key ---
    api_key_phrases = (
        "api key",
        "api_key",
        "api key not valid",
        "api_key_invalid",
        "invalid api key",
    )
    if exc_cls_lower == "invalidargument":
        return any(phrase in exc_str for phrase in api_key_phrases)

    # --- Message-based auth signals (applies to any exception type) ---
    msg_auth_signals = (
        "unauthorized",
        "403",
        "401",
        "invalid api key",
        "api key not valid",
        "api_key_invalid",
        "authentication",
        "unauthenticated",
        "permission denied",
    )
    return any(sig in exc_str for sig in msg_auth_signals)


async def _embed_real(texts: list[str]) -> list[list[float]]:
    """Call Google's text-embedding-004 via langchain_google_genai.

    Raises on any error — the caller (embed()) handles fallback policy
    so that auth errors and transient errors can be treated differently.
    """
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    # Lazy import — never executed in stub mode so tests don't need the package.
    from langchain_google_genai import GoogleGenerativeAIEmbeddings  # type: ignore[import]

    embedder = GoogleGenerativeAIEmbeddings(
        model="models/text-embedding-004",
        google_api_key=api_key,
    )
    raw: list[list[float]] = await embedder.aembed_documents(texts)
    return [_l2_norm(vec) for vec in raw]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def embed(texts: list[str]) -> list[list[float]]:
    """Return one L2-normalized 768-float vector per text in `texts`.

    Routing:
      * is_stub() → deterministic offline stub (no network, no key needed).
      * otherwise  → real Gemini text-embedding-004.

    Error policy (real path only):
      * Auth/config errors (invalid key, 401/403): logged at ERROR and re-raised.
        Silently returning stub vectors for an auth failure would mix embedding
        spaces and corrupt the vector store.
      * Transient errors (timeout, rate-limit, 5xx, missing package): logged at
        WARNING, falls back to stub so the service degrades gracefully.
    """
    if not texts:
        return []
    if is_stub():
        return await _embed_stub(texts)
    try:
        return await _embed_real(texts)
    except Exception as exc:  # noqa: BLE001
        if _is_auth_error(exc):
            logger.error(
                "embeddings: auth/config error with GEMINI_API_KEY (%s: %s); "
                "NOT falling back to stub — this would corrupt the vector store. "
                "Fix the key or set EMBED_PROVIDER=stub to use offline mode.",
                type(exc).__name__,
                exc,
            )
            raise
        logger.warning(
            "embeddings: real Gemini call failed (%s: %s); falling back to stub",
            type(exc).__name__,
            exc,
        )
        return await _embed_stub(texts)
