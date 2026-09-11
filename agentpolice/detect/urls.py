"""URL extraction and comparison helpers."""

from __future__ import annotations

import re

URL_RE = re.compile(
    r"""(?P<scheme>https?|ftp)://(?P<hostport>[^\s/?\#"'`\\|;)>\]}]+)(?P<rest>[^\s"'`\\|;)>\]}]*)""",
    re.IGNORECASE,
)

# Public-suffix fragments that need three labels to reach a registrable domain.
# Not exhaustive; agent-police only uses this to decide "same owner or not", and
# errs towards treating a change as significant.
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "com.au", "net.au", "org.au",
    "co.jp", "or.jp", "ne.jp", "ac.jp",
    "com.br", "com.mx", "com.tr", "com.tw", "com.hk", "com.sg",
    "co.kr", "or.kr",
    "co.in", "net.in", "org.in",
    "co.nz", "co.za",
    "github.io", "gitlab.io", "pages.dev", "workers.dev", "vercel.app",
    "netlify.app", "herokuapp.com", "duckdns.org", "ngrok.io", "ngrok-free.app",
    "b-cdn.net", "r2.dev", "trycloudflare.com",
}

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


class Url:
    """A URL occurrence inside a larger string."""

    __slots__ = ("end", "host", "path", "port", "raw", "scheme", "start")

    def __init__(self, raw: str, scheme: str, hostport: str, rest: str, start: int, end: int):
        self.raw = raw
        self.scheme = scheme.lower()
        host, _, port = hostport.partition(":")
        # strip userinfo if present
        if "@" in host:
            host = host.rsplit("@", 1)[1]
        self.host = host.lower().rstrip(".")
        self.port = port or None
        self.path = rest
        self.start = start
        self.end = end

    @property
    def registrable(self) -> str:
        """Best-effort registrable domain ("example.co.uk" from "a.b.example.co.uk")."""
        host = self.host
        if IPV4_RE.match(host) or ":" in host:
            return host
        labels = host.split(".")
        if len(labels) <= 2:
            return host
        last_two = ".".join(labels[-2:])
        last_three = ".".join(labels[-3:])
        if last_two in MULTI_LABEL_SUFFIXES and len(labels) >= 3:
            return last_three
        return last_two

    @property
    def is_ip_literal(self) -> bool:
        return bool(IPV4_RE.match(self.host)) or ":" in self.host

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Url({self.raw!r})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Url) and self.raw == other.raw

    def __hash__(self) -> int:
        return hash(self.raw)


def extract_urls(text: str) -> list[Url]:
    """Return every http/https/ftp URL occurring in *text*, in order."""
    out: list[Url] = []
    for m in URL_RE.finditer(text or ""):
        out.append(
            Url(
                raw=m.group(0),
                scheme=m.group("scheme"),
                hostport=m.group("hostport"),
                rest=m.group("rest"),
                start=m.start(),
                end=m.end(),
            )
        )
    return out


def same_owner(a: Url, b: Url) -> bool:
    """True when two URLs plausibly belong to the same operator."""
    return a.registrable == b.registrable
