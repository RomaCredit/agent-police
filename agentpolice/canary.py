"""Canary tokens for AC-2 (passive secret exfiltration).

AC-2 leaves the traffic unmodified, so it cannot be detected by diffing a
response. The only workable signal is the one the paper used: plant a credential
that nobody legitimate would ever use, then watch for somebody using it.

What the built-in collector can see:
  * url  - an HTTPS URL on the collector host; fires when something fetches it
  * dns  - a hostname under the collector's delegated zone; fires on resolution

What it cannot see (the token is issued, but only your own infrastructure can
observe the use): AWS keys, GitHub PATs, Slack tokens, Ethereum private keys.
Those are emitted as clearly-labelled decoys so you can wire them to a canary
service you control.
"""

from __future__ import annotations

import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

TOKEN_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"

OBSERVABLE_KINDS = frozenset({"url", "dns"})
DECOY_KINDS = frozenset({"aws", "github", "slack", "openai", "eth", "pem"})


def new_token(length: int = 20) -> str:
    """DNS-label-safe random token."""
    return "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(length))


@dataclass(slots=True)
class Canary:
    token: str
    kind: str
    value: str
    """The literal string planted in the probe traffic."""
    placement: str
    """Where it was planted: system_prompt, user_message, tool_result, tool_description."""
    observable: bool
    created_at: float = field(default_factory=time.time)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "kind": self.kind,
            "value": self.value,
            "placement": self.placement,
            "observable": self.observable,
            "created_at": self.created_at,
            "note": self.note,
        }


@dataclass(slots=True)
class CanaryHit:
    token: str
    kind: str
    at: float
    source_ip: str | None = None
    user_agent: str | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token, "kind": self.kind, "at": self.at,
            "source_ip": self.source_ip, "user_agent": self.user_agent,
            "detail": self.detail,
        }


class CanaryProvider(ABC):
    """Issues canaries and, where possible, reports whether they were used."""

    @abstractmethod
    def issue(self, kind: str, placement: str) -> Canary: ...

    @abstractmethod
    def hits(self, tokens: list[str]) -> list[CanaryHit]: ...

    def issue_set(self, placement: str, kinds: list[str] | None = None) -> list[Canary]:
        kinds = kinds or ["url", "dns", "aws", "github", "slack", "eth"]
        return [self.issue(kind, placement) for kind in kinds]


def _decoy_value(kind: str, token: str) -> tuple[str, str]:
    """Return (value, note) for a credential-shaped decoy.

    These are syntactically plausible but non-functional. They exist so a
    router's secret scanner matches on them (Listing 1 of the paper lists the
    exact patterns); observing the *use* needs your own canary infrastructure.
    """
    upper = token.upper()
    if kind == "aws":
        return (f"AKIA{upper[:16]}",
                "AWS-shaped decoy; detect use via CloudTrail on a canary account you own")
    if kind == "github":
        return (f"ghp_{token}{token[:16]}"[:40],
                "GitHub PAT-shaped decoy; detect use via your own audit log")
    if kind == "slack":
        return (f"xoxb-{int(time.time())}-{token}",
                "Slack bot-token-shaped decoy")
    if kind == "openai":
        return (f"sk-proj-{token}{token}"[:56],
                "OpenAI-key-shaped decoy")
    if kind == "eth":
        return ("0x" + secrets.token_hex(32),
                "Ethereum private-key-shaped decoy; fund only a nominal balance if you wire it up")
    if kind == "pem":
        blob = secrets.token_urlsafe(180)
        return ("-----BEGIN RSA PRIVATE KEY-----\n" + blob + "\n-----END RSA PRIVATE KEY-----",
                "PEM-shaped decoy")
    raise ValueError(f"unknown decoy kind {kind!r}")


class LocalCanaryProvider(CanaryProvider):
    """Issues canaries against a collector this process can query directly."""

    def __init__(self, http_base: str, dns_zone: str | None, store: CanaryStore):
        self.http_base = http_base.rstrip("/")
        self.dns_zone = dns_zone.strip(".") if dns_zone else None
        self.store = store

    def issue(self, kind: str, placement: str) -> Canary:
        token = new_token()
        if kind == "url":
            value = f"{self.http_base}/c/{token}"
            canary = Canary(token, kind, value, placement, True,
                            note="fires when anything fetches this URL")
        elif kind == "dns":
            if not self.dns_zone:
                return self.issue("url", placement)
            value = f"{token}.{self.dns_zone}"
            canary = Canary(token, kind, value, placement, True,
                            note="fires when anything resolves this hostname")
        else:
            value, note = _decoy_value(kind, token)
            canary = Canary(token, kind, value, placement, False, note=note)
        self.store.register(canary)
        return canary

    def hits(self, tokens: list[str]) -> list[CanaryHit]:
        return self.store.hits(tokens)


class NullCanaryProvider(CanaryProvider):
    """Offline mode: issues non-resolving decoys and never reports hits."""

    def issue(self, kind: str, placement: str) -> Canary:
        token = new_token()
        if kind in ("url", "dns"):
            host = f"{token}.canary.invalid"
            value = f"https://{host}/probe" if kind == "url" else host
            return Canary(token, kind, value, placement, False,
                          note="offline mode: no collector configured, use cannot be observed")
        value, note = _decoy_value(kind, token)
        return Canary(token, kind, value, placement, False, note=note)

    def hits(self, tokens: list[str]) -> list[CanaryHit]:
        return []


class CanaryStore(ABC):
    """Persistence for issued canaries and observed hits."""

    @abstractmethod
    def register(self, canary: Canary) -> None: ...

    @abstractmethod
    def record_hit(self, hit: CanaryHit) -> None: ...

    @abstractmethod
    def hits(self, tokens: list[str]) -> list[CanaryHit]: ...

    @abstractmethod
    def lookup(self, token: str) -> Canary | None: ...


class MemoryCanaryStore(CanaryStore):
    def __init__(self) -> None:
        self._canaries: dict[str, Canary] = {}
        self._hits: list[CanaryHit] = []

    def register(self, canary: Canary) -> None:
        self._canaries[canary.token] = canary

    def record_hit(self, hit: CanaryHit) -> None:
        self._hits.append(hit)

    def hits(self, tokens: list[str]) -> list[CanaryHit]:
        wanted = set(tokens)
        return [h for h in self._hits if h.token in wanted]

    def lookup(self, token: str) -> Canary | None:
        return self._canaries.get(token)


class HostedCanaryProvider(CanaryProvider):
    """Issues canaries against a collector running on another host.

    The collector only records a callback for a token it already knows, so
    every observable canary must be registered with it. Without that step the
    whole AC-2 path is silently inert: the audit plants canary URLs pointing at
    the collector, the collector drops the callbacks as unknown tokens, and the
    report cheerfully says to check back later.

    Registration failure is reported, never swallowed: an audit whose canaries
    cannot be observed has to say so rather than imply coverage it lacks.
    """

    def __init__(self, base_url: str, dns_zone: str | None, audit_id: str,
                 *, timeout: float = 10.0):
        self.http_base = base_url.rstrip("/")
        self.dns_zone = dns_zone.strip(".") if dns_zone else None
        self.audit_id = audit_id
        self.timeout = timeout
        self._pending: list[Canary] = []
        self.registered = 0
        self.error: str | None = None

    def issue(self, kind: str, placement: str) -> Canary:
        token = new_token()
        if kind == "url":
            canary = Canary(token, kind, f"{self.http_base}/c/{token}", placement, True,
                            note="fires when anything fetches this URL")
        elif kind == "dns":
            if not self.dns_zone:
                return self.issue("url", placement)
            canary = Canary(token, kind, f"{token}.{self.dns_zone}", placement, True,
                            note="fires when anything resolves this hostname")
        else:
            value, note = _decoy_value(kind, token)
            return Canary(token, kind, value, placement, False, note=note)
        self._pending.append(canary)
        return canary

    def flush(self) -> None:
        """Register everything issued since the last flush with the collector."""
        if not self._pending:
            return
        import httpx

        batch = [c.to_dict() for c in self._pending]
        self._pending = []
        try:
            response = httpx.post(
                f"{self.http_base}/api/canary/register",
                json={"audit_id": self.audit_id, "canaries": batch},
                timeout=self.timeout,
            )
            response.raise_for_status()
            self.registered += int(response.json().get("registered", 0))
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"

    def hits(self, tokens: list[str]) -> list[CanaryHit]:
        self.flush()
        if not tokens:
            return []
        import httpx

        try:
            response = httpx.get(f"{self.http_base}/api/canary/{self.audit_id}",
                                 timeout=self.timeout)
            response.raise_for_status()
            wanted = set(tokens)
            return [
                CanaryHit(h["token"], h["kind"], h["at"], h.get("source_ip"),
                          h.get("user_agent"), h.get("detail", ""))
                for h in response.json().get("hits", [])
                if h["token"] in wanted
            ]
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
            return []
