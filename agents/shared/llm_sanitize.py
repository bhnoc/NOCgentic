"""Sanitize text on its way to an external LLM.

One function, because it was four identical copies. Every agent applied the same
two scrubbers and the same length cap, so a change to the policy meant editing
four files and hoping none were missed. That is exactly how the old internal-IP
regex drifted: five copies, one of them fixed, four left leaking an octet.

The two scrubbers are deliberately separate modules with separate concerns:
  ipscope   decides which ADDRESSES may be shown (scope allowlist)
  credscrub strips CREDENTIALS (and preserves hash IOCs)
This just composes them in the order the LLM boundary needs.
"""

from __future__ import annotations

import credscrub
import ipscope

# Prompt-budget guard, not a security control. Long enough for a real alert
# payload, short enough that one oversized field cannot crowd out the analyst's
# actual question. The scrubbers run BEFORE the cut so a secret can never survive
# by sitting past the boundary.
MAX_LLM_CHARS = 8000

__all__ = ["MAX_LLM_CHARS", "sanitize_for_llm"]


def sanitize_for_llm(text: str) -> str:
    """Redact out-of-scope addresses and credentials, then cap the length."""
    text = ipscope.redact_text(text)
    text = credscrub.scrub_secrets(text)
    return text[:MAX_LLM_CHARS]
