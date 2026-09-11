"""Passive inspection: judge a command with no ground truth to diff against.

The active probes are strictly better, because they know the right answer.
This exists for the case where all you have is a command your agent is about
to run. Everything here is a heuristic, so findings are worded as "worth
checking", never as proof.
"""

from __future__ import annotations

import re
from typing import Any

from .toolcall import parse_installs, split_chain
from .typosquat import assess_standalone
from .urls import extract_urls

# Hosts where anyone can stand up content under their own subdomain, so the
# registrable domain tells you nothing about who controls the payload.
SHARED_TENANCY_SUFFIXES = (
    "duckdns.org", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "workers.dev",
    "pages.dev", "vercel.app", "netlify.app", "herokuapp.com", "b-cdn.net", "r2.dev",
    "github.io", "gitlab.io", "glitch.me", "repl.co", "oast.fun", "requestbin.net",
    "webhook.site", "0x0.st", "transfer.sh", "gofile.io", "file.io", "pastebin.com",
)

SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
              "rb.gy", "shorturl.at", "s.id")

PIPE_TO_SHELL_RE = re.compile(
    r"(curl|wget|fetch)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|k|da)?sh\b", re.IGNORECASE)
BASE64_PIPE_RE = re.compile(
    r"base64\s+(-d|--decode)[^|;&]*\|\s*(sudo\s+)?(ba|z|k|da)?sh\b", re.IGNORECASE)
ECHO_DECODE_RE = re.compile(
    r"(echo|printf)\s+[\"']?[A-Za-z0-9+/=]{40,}[\"']?\s*\|\s*base64", re.IGNORECASE)

PERSISTENCE_PATHS = (
    "/etc/cron", "crontab", "/etc/systemd", "~/.bashrc", "~/.zshrc", "~/.profile",
    "/etc/profile.d", "~/.ssh/authorized_keys", "LaunchAgents", "/etc/sudoers",
    "~/.claude/settings.json", "~/.codex/config",
)


def _item(severity: str, title: str, detail: str, **extra: Any) -> dict[str, Any]:
    return {"severity": severity, "title": title, "detail": detail, **extra}


def inspect_command(command: str) -> list[dict[str, Any]]:
    """Flag shapes in *command* that are worth a second look."""
    results: list[dict[str, Any]] = []
    if not command or not command.strip():
        return results

    if PIPE_TO_SHELL_RE.search(command):
        results.append(_item(
            "high", "Fetched script piped straight to a shell",
            "Whatever the server returns is executed immediately, so a single rewritten "
            "URL is enough for arbitrary code execution. Download to a file, read it, "
            "then run it.",
        ))
    if BASE64_PIPE_RE.search(command) or ECHO_DECODE_RE.search(command):
        results.append(_item(
            "high", "Base64-decoded content piped to a shell",
            "The payload is obscured from review. Decode it separately and read it first.",
        ))

    for url in extract_urls(command):
        if url.is_ip_literal:
            results.append(_item(
                "high", "Fetch target is a raw IP address",
                f"{url.raw} bypasses DNS and certificate name checks entirely.",
                url=url.raw,
            ))
        elif url.scheme == "http":
            results.append(_item(
                "medium", "Plaintext HTTP download",
                f"{url.raw} is fetched without TLS, so anything on the path can replace it.",
                url=url.raw,
            ))
        if url.registrable in SHORTENERS:
            results.append(_item(
                "high", "URL shortener hides the real destination",
                f"{url.raw} resolves somewhere you cannot see from the command.",
                url=url.raw,
            ))
        elif any(url.host.endswith(s) for s in SHARED_TENANCY_SUFFIXES):
            results.append(_item(
                "medium", "Shared-tenancy host",
                f"{url.host} lets anyone publish under their own subdomain, so the domain "
                "name is not evidence of who controls the content.",
                url=url.raw,
            ))

    for spec in parse_installs(command):
        for package in spec.packages:
            verdict = assess_standalone(package, spec.ecosystem)
            if verdict.suspicious:
                results.append(_item(
                    "high" if verdict.confidence == "high" else "medium",
                    "Package name resembles a popular package",
                    f"{package!r}: {verdict.detail}. Confirm this is the dependency you "
                    "meant before it lands in a lockfile.",
                    package=package, ecosystem=spec.ecosystem, nearest=verdict.target,
                ))

    lowered = command.lower()
    for path in PERSISTENCE_PATHS:
        if path.lower() in lowered:
            results.append(_item(
                "medium", "Touches a persistence location",
                f"The command references {path}, which survives the current session.",
                path=path,
            ))
            break

    segments = split_chain(command)
    if len(segments) >= 4:
        results.append(_item(
            "low", "Long command chain",
            f"{len(segments)} commands are chained together, which makes review harder and "
            "gives an injected step somewhere to hide.",
        ))

    return results
