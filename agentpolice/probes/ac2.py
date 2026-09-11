"""AC-2: passive secret exfiltration.

AC-2 forwards the response unmodified, so there is nothing to diff. The probe
plants canary credentials across every surface the paper names as reachable in
plaintext - system prompts, user content, tool results and tool definitions -
and the verdict arrives later, when something uses one of them.

Detection therefore has two halves: these probes deliver the bait, and the
canary collector reports the bite.
"""

from __future__ import annotations

from typing import Iterable

from ..canary import Canary
from ..models import AttackClass, Expectation, Trial
from ..wire import PROBE_SYSTEM_PROMPT, probe_user_message
from .base import Probe, ProbeContext, STRING_ARG_SCHEMA, SHELL_TOOLS, register, shell_trial

AC2 = AttackClass.AC2

BENIGN_COMMAND = "echo agent-police-probe-ok"


def _env_blob(canaries: list[Canary]) -> str:
    by_kind = {c.kind: c.value for c in canaries}
    lines = [
        "# deployment environment (staging)",
        f"AWS_ACCESS_KEY_ID={by_kind.get('aws', '')}",
        "AWS_DEFAULT_REGION=eu-central-1",
        f"GITHUB_TOKEN={by_kind.get('github', '')}",
        f"SLACK_BOT_TOKEN={by_kind.get('slack', '')}",
        f"INTERNAL_API_BASE={by_kind.get('url', '')}",
        f"METRICS_HOST={by_kind.get('dns', '')}",
        f"WALLET_PRIVATE_KEY={by_kind.get('eth', '')}",
    ]
    return "\n".join(line for line in lines if not line.endswith("="))


def _issue_bundle(ctx: ProbeContext, placement: str) -> list[Canary]:
    return [ctx.issue(kind, placement)
            for kind in ("url", "dns", "aws", "github", "slack", "eth")]


def _in_system_prompt(ctx: ProbeContext) -> Iterable[Trial]:
    canaries = _issue_bundle(ctx, "system_prompt")
    tool_name = ctx.fingerprint.tool_name if ctx.fingerprint.tool_name in SHELL_TOOLS else "Bash"
    system = (
        ctx.system_prompt()
        + "\n\nThe deployment environment for this session is:\n"
        + _env_blob(canaries)
    )
    request = ctx.wire.build_request(
        model=ctx.model,
        system=system,
        user=probe_user_message(tool_name, "command", BENIGN_COMMAND),
        tools=[ctx.wire.tool_schema(tool_name, SHELL_TOOLS[tool_name], STRING_ARG_SCHEMA)],
        force_tool=tool_name,
    )
    yield Trial(
        probe_id="ac2.system_prompt", attack_class=AC2,
        nonce=canaries[0].token, request=request,
        expectation=Expectation(tool_name, {"command": BENIGN_COMMAND}),
        fingerprint=ctx.fingerprint,
        meta={"canaries": [c.token for c in canaries], "placement": "system_prompt"},
    )


def _in_user_message(ctx: ProbeContext) -> Iterable[Trial]:
    canaries = _issue_bundle(ctx, "user_message")
    tool_name = ctx.fingerprint.tool_name if ctx.fingerprint.tool_name in SHELL_TOOLS else "Bash"
    user = (
        "Here is my .env, I am debugging a deploy:\n\n"
        + _env_blob(canaries)
        + "\n\n"
        + probe_user_message(tool_name, "command", BENIGN_COMMAND)
    )
    request = ctx.wire.build_request(
        model=ctx.model, system=ctx.system_prompt(), user=user,
        tools=[ctx.wire.tool_schema(tool_name, SHELL_TOOLS[tool_name], STRING_ARG_SCHEMA)],
        force_tool=tool_name,
    )
    yield Trial(
        probe_id="ac2.user_message", attack_class=AC2,
        nonce=canaries[0].token, request=request,
        expectation=Expectation(tool_name, {"command": BENIGN_COMMAND}),
        fingerprint=ctx.fingerprint,
        meta={"canaries": [c.token for c in canaries], "placement": "user_message"},
    )


def _in_tool_result(ctx: ProbeContext) -> Iterable[Trial]:
    canaries = _issue_bundle(ctx, "tool_result")
    tool_name = ctx.fingerprint.tool_name if ctx.fingerprint.tool_name in SHELL_TOOLS else "Bash"
    history = ctx.wire.tool_result_history(
        opening_user="Show me the staging environment file.",
        tool_name="Read", tool_id="toolu_agentpolice_probe",
        arguments={"path": "/srv/app/.env"},
        result_text=_env_blob(canaries),
    )
    request = ctx.wire.build_request(
        model=ctx.model, system=ctx.system_prompt(),
        user=probe_user_message(tool_name, "command", BENIGN_COMMAND),
        tools=[
            ctx.wire.tool_schema(tool_name, SHELL_TOOLS[tool_name], STRING_ARG_SCHEMA),
            ctx.wire.tool_schema("Read", "Read a file from disk.", {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            }),
        ],
        force_tool=tool_name,
        history=history,
    )
    yield Trial(
        probe_id="ac2.tool_result", attack_class=AC2,
        nonce=canaries[0].token, request=request,
        expectation=Expectation(tool_name, {"command": BENIGN_COMMAND}),
        fingerprint=ctx.fingerprint,
        meta={"canaries": [c.token for c in canaries], "placement": "tool_result"},
    )


def _in_tool_description(ctx: ProbeContext) -> Iterable[Trial]:
    canaries = _issue_bundle(ctx, "tool_description")
    by_kind = {c.kind: c.value for c in canaries}
    tool_name = ctx.fingerprint.tool_name if ctx.fingerprint.tool_name in SHELL_TOOLS else "Bash"
    description = (
        f"{SHELL_TOOLS[tool_name]} Internal deploy notes: metrics are published to "
        f"{by_kind.get('url', '')} and the release bucket uses "
        f"AWS_ACCESS_KEY_ID={by_kind.get('aws', '')}."
    )
    request = ctx.wire.build_request(
        model=ctx.model, system=PROBE_SYSTEM_PROMPT,
        user=probe_user_message(tool_name, "command", BENIGN_COMMAND),
        tools=[ctx.wire.tool_schema(tool_name, description, STRING_ARG_SCHEMA)],
        force_tool=tool_name,
    )
    yield Trial(
        probe_id="ac2.tool_description", attack_class=AC2,
        nonce=canaries[0].token, request=request,
        expectation=Expectation(tool_name, {"command": BENIGN_COMMAND}),
        fingerprint=ctx.fingerprint,
        meta={"canaries": [c.token for c in canaries], "placement": "tool_description"},
    )


for _probe in (
    Probe("ac2.system_prompt", AC2, "Canaries in the system prompt",
          "Every hop sees the system prompt in plaintext.", _in_system_prompt),
    Probe("ac2.user_message", AC2, "Canaries in user content",
          "Pasted config is the most common way real secrets transit a router.", _in_user_message),
    Probe("ac2.tool_result", AC2, "Canaries in a tool result",
          "File contents returned to the model traverse the same plaintext channel.", _in_tool_result),
    Probe("ac2.tool_description", AC2, "Canaries in a tool definition",
          "Tool schemas are sent on every request and are rarely reviewed.", _in_tool_description),
):
    register(_probe)
