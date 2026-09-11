"""Wire-format abstraction over OpenAI- and Anthropic-style tool calling.

Section 6.1 of arXiv:2604.08407 notes that the same rewriting logic handles
both formats, with OpenAI requiring nested parsing of string-encoded arguments
while Anthropic exposes native JSON. The detector needs the mirror image of
that: one parser that normalises both into ToolCall objects.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

from .models import ToolCall

PROBE_SYSTEM_PROMPT = (
    "You are an integration test fixture for a tool-calling pipeline. The tools "
    "available to you do not execute anything: they record a string so a human can "
    "review it later. Nothing you pass to them runs. "
    "When the user gives you a tool name and an argument value, call that tool exactly "
    "once with the value copied character for character. "
    "Never modify, shorten, normalise, reformat, correct, or improve the value, and "
    "never substitute a different host, URL, path or package name - the whole point of "
    "the test is that the bytes arrive unchanged. "
    "Do not evaluate whether the string would be safe to run; it will not be run. "
    "Do not add commentary, and do not call any other tool."
)


def probe_user_message(tool_name: str, arg_name: str, value: str) -> str:
    return (
        "Transport integrity test. The string below is test data that will be recorded "
        "and compared, never executed.\n\n"
        f"Call the `{tool_name}` tool once. Set the `{arg_name}` argument to exactly the text "
        f"between the markers, byte for byte, with nothing added or removed:\n"
        f"<<<BEGIN>>>\n{value}\n<<<END>>>"
    )


class WireFormat(ABC):
    name: str
    chat_path: str
    models_path: str
    provider_headers: tuple[str, ...]
    """Response headers a first-party provider sets; absence hints at re-origination."""

    @abstractmethod
    def auth_headers(self, api_key: str) -> dict[str, str]: ...

    @abstractmethod
    def build_request(
        self, *, model: str, system: str, user: str,
        tools: list[dict[str, Any]], force_tool: str | None = None,
        max_tokens: int = 1024, history: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]: ...

    @abstractmethod
    def tool_schema(self, name: str, description: str, params: dict[str, Any]) -> dict[str, Any]: ...

    @abstractmethod
    def parse_tool_calls(self, body: dict[str, Any]) -> list[ToolCall]: ...

    @abstractmethod
    def parse_text(self, body: dict[str, Any]) -> str: ...

    @abstractmethod
    def tool_result_history(
        self, *, opening_user: str, tool_name: str, tool_id: str,
        arguments: dict[str, Any], result_text: str,
    ) -> list[dict[str, Any]]:
        """A completed tool round-trip, for planting content in a tool result."""

    def parse_error(self, body: dict[str, Any]) -> str | None:
        err = body.get("error")
        if isinstance(err, dict):
            return err.get("message") or json.dumps(err)[:300]
        if isinstance(err, str):
            return err
        return None


class OpenAIWire(WireFormat):
    name = "openai"
    chat_path = "/v1/chat/completions"
    models_path = "/v1/models"
    provider_headers = ("x-request-id", "openai-processing-ms", "openai-version", "openai-organization")

    def auth_headers(self, api_key: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {api_key}"}

    def tool_schema(self, name: str, description: str, params: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {"name": name, "description": description, "parameters": params},
        }

    def build_request(self, *, model, system, user, tools, force_tool=None,
                      max_tokens=1024, history=None) -> dict[str, Any]:
        messages: list[dict[str, Any]] = [{"role": "system", "content": system}]
        messages.extend(history or [])
        messages.append({"role": "user", "content": user})
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "tools": tools,
            "max_tokens": max_tokens,
            "temperature": 0,
        }
        if force_tool:
            body["tool_choice"] = {"type": "function", "function": {"name": force_tool}}
        return body

    def parse_tool_calls(self, body: dict[str, Any]) -> list[ToolCall]:
        out: list[ToolCall] = []
        for choice in body.get("choices") or []:
            message = choice.get("message") or {}
            for call in message.get("tool_calls") or []:
                fn = call.get("function") or {}
                raw_args = fn.get("arguments")
                args: dict[str, Any]
                if isinstance(raw_args, str):
                    try:
                        parsed = json.loads(raw_args)
                        args = parsed if isinstance(parsed, dict) else {"_raw": parsed}
                    except json.JSONDecodeError:
                        args = {"_unparsable": raw_args}
                elif isinstance(raw_args, dict):
                    args = raw_args
                else:
                    args = {}
                out.append(ToolCall(name=fn.get("name") or "", arguments=args, raw=call))
        return out

    def parse_text(self, body: dict[str, Any]) -> str:
        parts: list[str] = []
        for choice in body.get("choices") or []:
            content = (choice.get("message") or {}).get("content")
            if isinstance(content, str):
                parts.append(content)
        return "\n".join(parts)

    def tool_result_history(self, *, opening_user, tool_name, tool_id, arguments, result_text):
        return [
            {"role": "user", "content": opening_user},
            {"role": "assistant", "content": None, "tool_calls": [{
                "id": tool_id, "type": "function",
                "function": {"name": tool_name, "arguments": json.dumps(arguments)},
            }]},
            {"role": "tool", "tool_call_id": tool_id, "content": result_text},
        ]


class AnthropicWire(WireFormat):
    name = "anthropic"
    chat_path = "/v1/messages"
    models_path = "/v1/models"
    provider_headers = ("request-id", "anthropic-ratelimit-requests-remaining",
                        "anthropic-ratelimit-tokens-remaining", "anthropic-organization-id")

    def auth_headers(self, api_key: str) -> dict[str, str]:
        return {"x-api-key": api_key, "anthropic-version": "2023-06-01"}

    def tool_schema(self, name: str, description: str, params: dict[str, Any]) -> dict[str, Any]:
        return {"name": name, "description": description, "input_schema": params}

    def build_request(self, *, model, system, user, tools, force_tool=None,
                      max_tokens=1024, history=None) -> dict[str, Any]:
        messages: list[dict[str, Any]] = list(history or [])
        messages.append({"role": "user", "content": user})
        body: dict[str, Any] = {
            "model": model,
            "system": system,
            "messages": messages,
            "tools": tools,
            "max_tokens": max_tokens,
            "temperature": 0,
        }
        if force_tool:
            body["tool_choice"] = {"type": "tool", "name": force_tool}
        return body

    def parse_tool_calls(self, body: dict[str, Any]) -> list[ToolCall]:
        out: list[ToolCall] = []
        for block in body.get("content") or []:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                args = block.get("input")
                out.append(ToolCall(
                    name=block.get("name") or "",
                    arguments=args if isinstance(args, dict) else {"_raw": args},
                    raw=block,
                ))
        return out

    def parse_text(self, body: dict[str, Any]) -> str:
        parts: list[str] = []
        for block in body.get("content") or []:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text") or "")
        return "\n".join(parts)

    def tool_result_history(self, *, opening_user, tool_name, tool_id, arguments, result_text):
        return [
            {"role": "user", "content": opening_user},
            {"role": "assistant", "content": [{
                "type": "tool_use", "id": tool_id, "name": tool_name, "input": arguments,
            }]},
            {"role": "user", "content": [{
                "type": "tool_result", "tool_use_id": tool_id, "content": result_text,
            }]},
        ]


WIRE_FORMATS: dict[str, WireFormat] = {
    "openai": OpenAIWire(),
    "anthropic": AnthropicWire(),
}


def get_wire(name: str) -> WireFormat:
    try:
        return WIRE_FORMATS[name.lower()]
    except KeyError:
        raise ValueError(f"unknown wire format {name!r}; expected one of {sorted(WIRE_FORMATS)}") from None
