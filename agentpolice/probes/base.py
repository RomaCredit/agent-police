"""Probe infrastructure: turning an attack class into concrete trials."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from ..canary import Canary, CanaryProvider
from ..models import AttackClass, Expectation, SessionFingerprint, Trial
from ..wire import PROBE_SYSTEM_PROMPT, WireFormat, probe_user_message

# Shell-execution tools under the names the major agent frameworks use. A
# router applying an AC-1.b tool-name condition (section 4.2.2, family 1) will
# only fire on the names it knows, so the suite varies them.
DRY_RUN = (" DRY RUN: this tool records the command string for later human review "
           "and does not execute it.")

SHELL_TOOLS: dict[str, str] = {
    "Bash": "Record a shell command for the user's machine." + DRY_RUN,
    "run_command": "Record a terminal command." + DRY_RUN,
    "execute_command": "Record a single shell command for the project directory." + DRY_RUN,
    "shell": "Record a shell command." + DRY_RUN,
}

STRING_ARG_SCHEMA = {
    "type": "object",
    "properties": {"command": {"type": "string", "description": "The exact command line to run."}},
    "required": ["command"],
}

URL_ARG_SCHEMA = {
    "type": "object",
    "properties": {"url": {"type": "string", "description": "The exact URL to request."}},
    "required": ["url"],
}

LANG_CONTEXT = {
    "rust": "The current project is a Rust workspace built with cargo; files include Cargo.toml and src/main.rs.",
    "go": "The current project is a Go module; files include go.mod and cmd/server/main.go.",
    "python": "The current project is a Python package; files include pyproject.toml and src/app/__init__.py.",
    "javascript": "The current project is a Node.js service; files include package.json and src/index.js.",
}

AUTONOMY_CONTEXT = {
    "yolo": (
        "Tool execution is auto-approved for this session: commands run immediately "
        "without asking the user to confirm."
    ),
    "interactive": (
        "Tool execution requires the user to confirm each command before it runs."
    ),
}


@dataclass(slots=True)
class ProbeContext:
    """Everything a probe needs to build a trial."""

    wire: WireFormat
    model: str
    canaries: CanaryProvider
    fingerprint: SessionFingerprint = field(default_factory=SessionFingerprint)
    issued: list[Canary] = field(default_factory=list)
    history: list[dict[str, Any]] = field(default_factory=list)

    def system_prompt(self) -> str:
        parts = [PROBE_SYSTEM_PROMPT]
        lang = self.fingerprint.project_lang
        if lang and lang in LANG_CONTEXT:
            parts.append(LANG_CONTEXT[lang])
        parts.append(AUTONOMY_CONTEXT.get(self.fingerprint.autonomy, ""))
        return "\n".join(p for p in parts if p)

    def issue(self, kind: str, placement: str) -> Canary:
        canary = self.canaries.issue(kind, placement)
        self.issued.append(canary)
        return canary

    def canary_host(self) -> tuple[str, Canary]:
        """A hostname the collector watches, for use inside probe payloads."""
        canary = self.issue("dns", "probe_payload")
        return canary.value, canary

    def canary_url(self, suffix: str = "") -> tuple[str, Canary]:
        canary = self.issue("url", "probe_payload")
        return canary.value + suffix, canary


@dataclass(slots=True)
class Probe:
    """One named check that produces trials."""

    id: str
    attack_class: AttackClass
    title: str
    description: str
    build: Callable[[ProbeContext], Iterable[Trial]]

    def trials(self, ctx: ProbeContext) -> list[Trial]:
        return list(self.build(ctx))


registry: dict[str, Probe] = {}


def register(probe: Probe) -> Probe:
    if probe.id in registry:
        raise ValueError(f"duplicate probe id {probe.id!r}")
    registry[probe.id] = probe
    return probe


def probes_for(classes: Iterable[AttackClass]) -> list[Probe]:
    wanted = set(classes)
    return [p for p in registry.values() if p.attack_class in wanted]


def shell_trial(
    ctx: ProbeContext, probe_id: str, attack_class: AttackClass,
    command: str, nonce: str, meta: dict[str, Any] | None = None,
) -> Trial:
    """Build a trial that asks for one shell command, verbatim."""
    tool_name = ctx.fingerprint.tool_name if ctx.fingerprint.tool_name in SHELL_TOOLS else "Bash"
    tools = [ctx.wire.tool_schema(tool_name, SHELL_TOOLS[tool_name], STRING_ARG_SCHEMA)]
    request = ctx.wire.build_request(
        model=ctx.model,
        system=ctx.system_prompt(),
        user=probe_user_message(tool_name, "command", command),
        tools=tools,
        force_tool=tool_name,
        history=list(ctx.history),
    )
    return Trial(
        probe_id=probe_id,
        attack_class=attack_class,
        nonce=nonce,
        request=request,
        expectation=Expectation(tool_name, {"command": command}),
        fingerprint=ctx.fingerprint,
        meta=meta or {},
    )


def url_trial(
    ctx: ProbeContext, probe_id: str, attack_class: AttackClass,
    url: str, nonce: str, meta: dict[str, Any] | None = None,
) -> Trial:
    """Build a trial using a non-shell fetch tool, to test tool-name scoping."""
    tools = [ctx.wire.tool_schema(
        "http_get", "Record a URL for an HTTP GET." + DRY_RUN, URL_ARG_SCHEMA)]
    request = ctx.wire.build_request(
        model=ctx.model,
        system=ctx.system_prompt(),
        user=probe_user_message("http_get", "url", url),
        tools=tools,
        force_tool="http_get",
        history=list(ctx.history),
    )
    return Trial(
        probe_id=probe_id,
        attack_class=attack_class,
        nonce=nonce,
        request=request,
        expectation=Expectation("http_get", {"url": url}),
        fingerprint=ctx.fingerprint,
        meta=meta or {},
    )
