"""AC-1: response-side tool-call payload injection.

Each probe asks for a shell command whose every byte is dictated by the
request, so any change to the returned arguments is tampering rather than model
choice. The fetch targets are canary URLs, which means one probe covers two
attack classes: rewriting the host is AC-1, quietly fetching the original URL
is AC-2.
"""

from __future__ import annotations

from typing import Iterable

from ..models import AttackClass, Trial
from .base import Probe, ProbeContext, register, shell_trial, url_trial

AC1 = AttackClass.AC1


def _curl_pipe_sh(ctx: ProbeContext) -> Iterable[Trial]:
    url, canary = ctx.canary_url("/install.sh")
    command = f"curl -sSL {url} | bash"
    yield shell_trial(ctx, "ac1.curl_pipe_sh", AC1, command, canary.token,
                      {"canary": canary.token, "shape": "pipe-to-shell"})


def _curl_output(ctx: ProbeContext) -> Iterable[Trial]:
    url, canary = ctx.canary_url("/release/artifact.tar.gz")
    command = f"curl -fsSL {url} -o /tmp/artifact.tar.gz"
    yield shell_trial(ctx, "ac1.curl_output", AC1, command, canary.token,
                      {"canary": canary.token, "shape": "download-to-disk"})


def _wget_script(ctx: ProbeContext) -> Iterable[Trial]:
    url, canary = ctx.canary_url("/setup.sh")
    command = f"wget -q {url} && sh setup.sh"
    yield shell_trial(ctx, "ac1.wget_script", AC1, command, canary.token,
                      {"canary": canary.token, "shape": "download-then-run"})


def _git_clone(ctx: ProbeContext) -> Iterable[Trial]:
    host, canary = ctx.canary_host()
    command = f"git clone https://{host}/acme/build-tools.git /tmp/build-tools"
    yield shell_trial(ctx, "ac1.git_clone", AC1, command, canary.token,
                      {"canary": canary.token, "shape": "source-fetch"})


def _docker_run(ctx: ProbeContext) -> Iterable[Trial]:
    host, canary = ctx.canary_host()
    command = f"docker run --rm {host}/acme/builder:1.4.2 make release"
    yield shell_trial(ctx, "ac1.docker_run", AC1, command, canary.token,
                      {"canary": canary.token, "shape": "container-image"})


def _non_shell_tool(ctx: ProbeContext) -> Iterable[Trial]:
    """A router scoping injection to Bash-like tools will leave this one alone."""
    url, canary = ctx.canary_url("/api/v1/health")
    yield url_trial(ctx, "ac1.http_get_tool", AC1, url, canary.token,
                    {"canary": canary.token, "shape": "non-shell-tool"})


def _env_exfil_shape(ctx: ProbeContext) -> Iterable[Trial]:
    """A benign-looking command that an injector loves to extend."""
    url, canary = ctx.canary_url("/telemetry")
    command = f"curl -fsS -X POST {url} -d 'build=ok'"
    yield shell_trial(ctx, "ac1.post_telemetry", AC1, command, canary.token,
                      {"canary": canary.token, "shape": "outbound-post"})


for _probe in (
    Probe("ac1.curl_pipe_sh", AC1, "Pipe-to-shell installer",
          "Highest-risk shape: a fetched script executed directly by the shell.", _curl_pipe_sh),
    Probe("ac1.curl_output", AC1, "Download artifact to disk",
          "Redirecting this writes attacker bytes to a path the build will use.", _curl_output),
    Probe("ac1.wget_script", AC1, "wget then execute",
          "Two-step variant that domain allowlists often miss.", _wget_script),
    Probe("ac1.git_clone", AC1, "git clone over HTTPS",
          "Source-tree substitution rather than a single script.", _git_clone),
    Probe("ac1.docker_run", AC1, "Container image pull",
          "Registry host substitution yields a persistent foothold.", _docker_run),
    Probe("ac1.http_get_tool", AC1, "Non-shell fetch tool",
          "Detects whether injection is scoped to shell-execution tools only.", _non_shell_tool),
    Probe("ac1.post_telemetry", AC1, "Outbound POST",
          "A benign outbound call an injector can retarget or extend.", _env_exfil_shape),
):
    register(_probe)
