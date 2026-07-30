"""
tool_provider.py — Minimal tool-calling provider abstraction for the investigator loop.

Provides a thin layer over LLM providers that supports single-tool function calling
(query_athena). GeminiToolProvider uses langchain_google_genai (lazy import so offline
tests work without it). FixtureProvider runs scripted turns for deterministic tests.

Usage:
    from tool_provider import get_tool_provider, FixtureProvider, ToolCall
"""

from __future__ import annotations

import copy
import logging
import os
from typing import Any, Protocol, TypedDict, runtime_checkable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ToolCall type
# ---------------------------------------------------------------------------

class ToolCall(TypedDict):
    id: str
    name: str
    arguments: dict


# ---------------------------------------------------------------------------
# ToolProvider Protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class ToolProvider(Protocol):
    """Provider that can chat with optional tool-calling support."""

    async def chat(
        self,
        messages: list,
        use_tools: bool = True,
        temperature: float = 0.3,
    ) -> tuple[str, list[ToolCall]]:
        """Send messages, return (text, tool_calls).

        text: the model's prose response (may be empty if it only called tools).
        tool_calls: list of ToolCall dicts (may be empty if no tools called).
        """
        ...

    def format_tool_result(self, tool_call_id: str, result: str) -> dict:
        """Format a tool result for appending to the message history."""
        ...


# ---------------------------------------------------------------------------
# GeminiToolProvider — production, uses langchain_google_genai (lazy import)
# ---------------------------------------------------------------------------

class GeminiToolProvider:
    """Tool-calling provider backed by Google Gemini via langchain_google_genai.

    langchain_google_genai is imported LAZILY inside __init__ so the module
    can be imported in offline test environments without triggering ImportError.
    """

    def __init__(self) -> None:
        # Lazy import — tests use FixtureProvider and never touch this path.
        from langchain_google_genai import ChatGoogleGenerativeAI  # noqa: F401 (lazy)
        from langchain_core.tools import StructuredTool
        from pydantic import BaseModel

        api_key = os.getenv("GEMINI_API_KEY", "")
        model = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")

        self._llm_base = ChatGoogleGenerativeAI(
            model=model,
            google_api_key=api_key,
            max_output_tokens=4096,
            temperature=0.3,
            timeout=120,
            max_retries=1,
        )

        # Define the single tool: query_athena
        class QueryAthenaInput(BaseModel):
            query: str

        def _query_athena_stub(query: str) -> str:  # noqa: ARG001
            # Never called — the real execution happens in the investigator loop.
            return ""

        self._tool = StructuredTool.from_function(
            func=_query_athena_stub,
            name="query_athena",
            description=(
                "Execute a SQL SELECT query against Athena to analyze Corelight/Zeek+Suricata logs. "
                "Always include a WHERE dt = 'YYYY-MM-DD' partition filter."
            ),
            args_schema=QueryAthenaInput,
        )
        self._llm_with_tools = self._llm_base.bind_tools([self._tool])
        self._llm_no_tools = self._llm_base

    async def chat(
        self,
        messages: list,
        use_tools: bool = True,
        temperature: float = 0.3,
    ) -> tuple[str, list[ToolCall]]:
        """Invoke Gemini, return (text, tool_calls)."""
        from langchain_core.messages import (
            SystemMessage, HumanMessage, AIMessage, ToolMessage
        )

        lc_messages = _to_langchain_messages(messages)
        llm = self._llm_with_tools if use_tools else self._llm_no_tools
        response: AIMessage = await llm.ainvoke(lc_messages)

        # Extract text
        raw = response.content
        if isinstance(raw, str):
            text = raw.strip()
        elif isinstance(raw, list):
            parts = []
            for block in raw:
                if isinstance(block, dict):
                    parts.append(block.get("text", ""))
                elif isinstance(block, str):
                    parts.append(block)
            text = "".join(parts).strip()
        else:
            text = str(raw).strip()

        # Extract tool calls — LangChain normalizes to [{name, args, id}]
        # st-9: args may be explicitly None on some streamed responses; coerce
        # to {} rather than letting dict(None) raise TypeError.  Also skip any
        # tool call with an empty name (would be a no-op and confuse the loop).
        tool_calls: list[ToolCall] = []
        for tc in (response.tool_calls or []):
            name = tc.get("name", "") or ""
            if not name:
                logger.warning("GeminiToolProvider: skipping tool call with empty name: %r", tc)
                continue
            args = tc.get("args") or {}
            tool_calls.append(ToolCall(
                id=tc.get("id", "") or "",
                name=name,
                arguments=dict(args),
            ))

        return text, tool_calls

    def format_tool_result(self, tool_call_id: str, result: str) -> dict:
        """Return a langchain ToolMessage-compatible dict."""
        return {
            "role": "tool",
            "tool_call_id": tool_call_id,
            "content": result,
        }


# ---------------------------------------------------------------------------
# Message conversion helper
# ---------------------------------------------------------------------------

def _to_langchain_messages(messages: list) -> list:
    """Convert plain dicts to LangChain message objects."""
    from langchain_core.messages import (
        SystemMessage, HumanMessage, AIMessage, ToolMessage
    )
    lc = []
    for m in messages:
        role = m.get("role", "")
        content = m.get("content", "")
        if role == "system":
            lc.append(SystemMessage(content=content))
        elif role == "user":
            if isinstance(content, list):
                # Tool results packed as a list — extract text
                text = " ".join(
                    item.get("content", "") if isinstance(item, dict) else str(item)
                    for item in content
                )
                lc.append(HumanMessage(content=text))
            else:
                lc.append(HumanMessage(content=str(content or "")))
        elif role == "assistant":
            tool_calls = m.get("tool_calls", [])
            if tool_calls:
                # Reconstruct AIMessage with tool_calls.
                # st-9: use .get() for id/name/arguments so a history entry
                # missing any key doesn't raise KeyError.
                lc.append(AIMessage(
                    content=content or "",
                    tool_calls=[
                        {
                            "id": tc.get("id", ""),
                            "name": tc.get("name", ""),
                            "args": tc.get("arguments", {}),
                        }
                        for tc in tool_calls
                    ],
                ))
            else:
                lc.append(AIMessage(content=str(content or "")))
        elif role == "tool":
            lc.append(ToolMessage(
                content=str(content or ""),
                tool_call_id=m.get("tool_call_id", ""),
            ))
        else:
            # Fallback: treat as human
            lc.append(HumanMessage(content=str(content or "")))
    return lc


# ---------------------------------------------------------------------------
# FixtureProvider — deterministic, offline, drives acid tests
# ---------------------------------------------------------------------------

class FixtureProvider:
    """Deterministic provider that returns pre-scripted turns.

    Each turn in `script` is either:
      {"text": str}                                     — finalize (no tool calls)
      {"tool_calls": [{"name": "query_athena", "arguments": {"query": sql}}]}

    Each call to chat() pops the next scripted turn. If the script is exhausted,
    raises IndexError (the depth guard should catch it first in normal usage).
    """

    def __init__(self, script: list[dict]) -> None:
        self._script = list(script)
        self._pos = 0
        # Records the messages list passed to each chat() call, so tests can
        # assert what system/user content the loop actually sent to the model
        # (e.g. that injected operational memory reached the system prompt).
        self.seen_messages: list[list] = []

    async def chat(
        self,
        messages: list,
        use_tools: bool = True,  # noqa: ARG002
        temperature: float = 0.3,  # noqa: ARG002
    ) -> tuple[str, list[ToolCall]]:
        # st-8: use copy.deepcopy so nested content/tool_calls lists in prior
        # messages cannot be mutated retroactively via later loop mutations.
        # Fixtures are small so the cost is negligible.
        self.seen_messages.append(copy.deepcopy(messages))
        if self._pos >= len(self._script):
            raise IndexError(
                f"FixtureProvider script exhausted at position {self._pos} "
                f"(script length {len(self._script)})"
            )
        turn = self._script[self._pos]
        self._pos += 1

        if "text" in turn:
            return turn["text"], []

        raw_calls = turn.get("tool_calls", [])
        tool_calls: list[ToolCall] = []
        for i, tc in enumerate(raw_calls):
            # st-9: coerce arguments to {} when explicitly None; use .get() for name
            args = tc.get("arguments") or {}
            tool_calls.append(ToolCall(
                id=tc.get("id", f"fixture_tc_{self._pos}_{i}"),
                name=tc.get("name", ""),
                arguments=dict(args),
            ))
        return "", tool_calls

    def format_tool_result(self, tool_call_id: str, result: str) -> dict:
        return {
            "role": "tool",
            "tool_call_id": tool_call_id,
            "content": result,
        }


# ---------------------------------------------------------------------------
# InfiniteToolProvider — depth-limit stress test helper
# ---------------------------------------------------------------------------

class InfiniteToolProvider:
    """Always returns a tool call, never finalizes. Used to test MAX_TOOL_DEPTH."""

    _counter: int = 0

    async def chat(
        self,
        messages: list,  # noqa: ARG002
        use_tools: bool = True,
        temperature: float = 0.3,  # noqa: ARG002
    ) -> tuple[str, list[ToolCall]]:
        if not use_tools:
            return "Depth cap summary.", []
        self._counter += 1
        return "", [ToolCall(
            id=f"inf_tc_{self._counter}",
            name="query_athena",
            arguments={"query": f"SELECT 1 FROM conn WHERE dt = '2026-07-30' -- step {self._counter}"},
        )]

    def format_tool_result(self, tool_call_id: str, result: str) -> dict:  # noqa: ARG002
        return {"role": "tool", "tool_call_id": tool_call_id, "content": result}


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def is_stub() -> bool:
    """Return True when GEMINI_API_KEY is unset (LLM unavailable)."""
    return not bool(os.getenv("GEMINI_API_KEY", "").strip())


def get_tool_provider() -> GeminiToolProvider:
    """Return a configured GeminiToolProvider (imports langchain lazily)."""
    return GeminiToolProvider()
