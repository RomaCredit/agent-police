"""Identify what software is answering, and whether it is first-party.

Running one of these routers is entirely normal and is never by itself a
finding. What matters is whether the operator knows an intermediary is there,
because a router is a full application-layer man-in-the-middle by design.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from typing import Any
from urllib.parse import urlsplit


@dataclass(slots=True)
class ControlResponse:
    """How the endpoint answers a path that cannot possibly exist.

    Many routers serve a single-page app and return 200 with the same HTML
    shell for every unrecognised path. Against those, "GET /foo returned 200"
    proves nothing at all, so agent-police measures the catch-all first and
    discards any check that merely reproduces it.
    """

    status: int | None = None
    content_type: str = ""
    body_len: int = 0
    body_head: str = ""

    @property
    def is_catch_all(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    def looks_like_control(self, status: int | None, content_type: str,
                           text: str) -> bool:
        if not self.is_catch_all or status != self.status:
            return False
        if content_type.split(";")[0].strip() != self.content_type.split(";")[0].strip():
            return False
        # Same shell, modulo a path echoed into the body.
        return abs(len(text) - self.body_len) <= max(64, self.body_len * 0.1)


@dataclass(slots=True)
class SignatureMatch:
    id: str
    name: str
    confidence: str
    note: str
    evidence: list[str] = field(default_factory=list)


@lru_cache(maxsize=1)
def _data() -> dict[str, Any]:
    raw = resources.files("agentpolice.data").joinpath("signatures.json").read_text("utf-8")
    return json.loads(raw)


def signatures() -> list[dict[str, Any]]:
    return _data().get("signatures", [])


def host_of(base_url: str) -> str:
    parts = urlsplit(base_url if "://" in base_url else "https://" + base_url)
    return (parts.hostname or "").lower()


def classify_host(base_url: str) -> tuple[str, str]:
    """Return (category, detail) for the endpoint host.

    Categories: first_party, known_aggregator, unknown.
    """
    host = host_of(base_url)
    d = _data()
    if host in d.get("first_party_hosts", []):
        return "first_party", f"{host} is a first-party model provider endpoint"
    for suffix in d.get("first_party_suffixes", []):
        if host.endswith(suffix):
            return "first_party", f"{host} is a first-party managed endpoint ({suffix})"
    if host in d.get("known_aggregators", []):
        return "known_aggregator", f"{host} is a publicly operated aggregator"
    return "unknown", f"{host} is not a first-party provider endpoint"


def _dig(body: dict[str, Any], dotted: str) -> Any:
    cur: Any = body
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


STRONG_CONSTRAINTS = ("json_has_key", "json_contains", "body_contains", "content_type")


def is_strong(check: dict[str, Any]) -> bool:
    """A check is strong when it inspects content, not just reachability."""
    return any(key in check for key in STRONG_CONSTRAINTS)


def check_matches(check: dict[str, Any], status: int | None,
                  body: dict[str, Any] | None, text: str,
                  content_type: str = "",
                  control: ControlResponse | None = None) -> str | None:
    """Return a human-readable evidence string if *check* is satisfied."""
    path = check.get("path", "/")

    if control is not None and control.looks_like_control(status, content_type, text):
        # Indistinguishable from the catch-all: this path does not exist.
        return None

    if "content_type" in check and check["content_type"] not in content_type.lower():
        return None

    if "status" in check:
        if status != check["status"]:
            return None
        evidence = f"GET {path} returned {status}"
    else:
        evidence = f"GET {path}"

    if "json_has_key" in check:
        if not isinstance(body, dict) or check["json_has_key"] not in body:
            return None
        evidence += f", JSON has key {check['json_has_key']!r}"

    if "json_contains" in check:
        if not isinstance(body, dict):
            return None
        for dotted, expected in check["json_contains"].items():
            actual = _dig(body, dotted)
            if isinstance(expected, str):
                if not isinstance(actual, str) or expected.lower() not in actual.lower():
                    return None
            elif actual != expected:
                return None
            evidence += f", {dotted}={actual!r}"

    if "body_contains" in check:
        if check["body_contains"].lower() not in (text or "").lower():
            return None
        evidence += f", body contains {check['body_contains']!r}"

    if "status" not in check and "json_has_key" not in check \
            and "json_contains" not in check and "body_contains" not in check:
        return None
    return evidence
