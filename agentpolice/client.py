"""HTTP client for talking to the endpoint under test.

Rules this module enforces:
  * the API key is never written to a log, an error string or a report;
  * redirects are not followed silently - a cross-host redirect is evidence;
  * every call is rate limited, so auditing does not look like abuse.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from .wire import WireFormat

DEFAULT_TIMEOUT = 90.0
USER_AGENT = "agent-police/0.1 (+https://security.romaapi.com)"


class RateLimiter:
    """Token bucket, so an audit stays well under any provider's limits."""

    def __init__(self, per_minute: float = 20.0):
        self.interval = 60.0 / max(per_minute, 0.1)
        self._lock = threading.Lock()
        self._next = 0.0

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            wait = self._next - now
            if wait > 0:
                time.sleep(wait)
                now = time.monotonic()
            self._next = now + self.interval


@dataclass(slots=True)
class TlsInfo:
    negotiated_protocol: str | None = None
    cipher: str | None = None
    subject: str | None = None
    issuer: str | None = None
    not_after: str | None = None
    sans: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "negotiated_protocol": self.negotiated_protocol,
            "cipher": self.cipher,
            "subject": self.subject,
            "issuer": self.issuer,
            "not_after": self.not_after,
            "sans": self.sans,
            "error": self.error,
        }


class PeerRejected(Exception):
    """The connection landed on an address the caller refuses to talk to."""


def _peer_address(response: httpx.Response) -> str | None:
    try:
        stream = response.extensions.get("network_stream")
        if stream is None:
            return None
        addr = stream.get_extra_info("server_addr")
        if isinstance(addr, (tuple, list)) and addr:
            return str(addr[0])
        return str(addr) if addr else None
    except Exception:  # pragma: no cover - defensive
        return None


def _is_public_address(address: str) -> bool:
    import ipaddress
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True  # not an address we can judge; leave the decision upstream
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


@dataclass(slots=True)
class HttpResult:
    ok: bool
    status: int | None
    body: dict[str, Any] | None
    text: str
    headers: dict[str, str]
    latency_ms: float
    error: str | None = None
    redirect_to: str | None = None
    tls: TlsInfo | None = None


def _flatten_name(pairs: Any) -> str | None:
    try:
        return ", ".join(f"{k}={v}" for rdn in pairs for (k, v) in rdn)
    except Exception:  # pragma: no cover - defensive
        return None


def _extract_tls(response: httpx.Response) -> TlsInfo:
    info = TlsInfo()
    try:
        stream = response.extensions.get("network_stream")
        if stream is None:
            info.error = "no network stream exposed"
            return info
        ssl_object = stream.get_extra_info("ssl_object")
        if ssl_object is None:
            info.error = "connection is not TLS"
            return info
        info.negotiated_protocol = ssl_object.version()
        cipher = ssl_object.cipher()
        info.cipher = cipher[0] if cipher else None
        cert = ssl_object.getpeercert()
        if cert:
            info.subject = _flatten_name(cert.get("subject"))
            info.issuer = _flatten_name(cert.get("issuer"))
            info.not_after = cert.get("notAfter")
            info.sans = [v for (t, v) in cert.get("subjectAltName", ()) if t == "DNS"]
    except Exception as exc:  # pragma: no cover - defensive
        info.error = f"{type(exc).__name__}: {exc}"
    return info


def normalize_base_url(base_url: str) -> str:
    """Strip a trailing /v1 or / so path joining is predictable."""
    parts = urlsplit(base_url.strip())
    if not parts.scheme:
        parts = urlsplit("https://" + base_url.strip())
    path = parts.path.rstrip("/")
    if path.endswith("/v1"):
        path = path[: -len("/v1")]
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


class RouterClient:
    """Talks to one endpoint under test."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        wire: WireFormat,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        rate_per_minute: float = 20.0,
        verify_tls: bool = True,
        require_public_peer: bool = False,
    ):
        self.base_url = normalize_base_url(base_url)
        self._api_key = api_key
        self.wire = wire
        self.limiter = RateLimiter(rate_per_minute)
        self.require_public_peer = require_public_peer
        """Re-check the peer address on every response.

        The hosted service validates the target before starting, but DNS can be
        rebound between that check and the connection. Checking where the
        socket actually landed closes that window.
        """
        self.tls: TlsInfo | None = None
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            verify=verify_tls,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )

    # -- key hygiene ----------------------------------------------------
    def redact(self, text: str) -> str:
        """Remove the API key from any string before it leaves this process."""
        if not text:
            return text
        out = text
        if self._api_key:
            out = out.replace(self._api_key, "[REDACTED_KEY]")
            if len(self._api_key) > 12:
                out = out.replace(self._api_key[:12], "[REDACTED_KEY]")
        return out

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "RouterClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- requests -------------------------------------------------------
    def _request(
        self, method: str, path: str, *, json_body: dict[str, Any] | None = None,
        authed: bool = True, key_override: str | None = None,
    ) -> HttpResult:
        self.limiter.acquire()
        url = self.base_url + path
        headers: dict[str, str] = {}
        if authed:
            headers.update(self.wire.auth_headers(key_override or self._api_key))
        if json_body is not None:
            headers["Content-Type"] = "application/json"

        start = time.perf_counter()
        try:
            response = self._client.request(method, url, json=json_body, headers=headers)
        except httpx.HTTPError as exc:
            return HttpResult(
                ok=False, status=None, body=None, text="", headers={},
                latency_ms=(time.perf_counter() - start) * 1000,
                error=self.redact(f"{type(exc).__name__}: {exc}"),
            )
        latency_ms = (time.perf_counter() - start) * 1000

        if self.require_public_peer:
            peer = _peer_address(response)
            if peer and not _is_public_address(peer):
                response.close()
                raise PeerRejected(
                    f"connection to {url} landed on non-public address {peer}"
                )

        if self.tls is None:
            self.tls = _extract_tls(response)

        body: dict[str, Any] | None = None
        text = response.text or ""
        try:
            parsed = response.json()
            body = parsed if isinstance(parsed, dict) else {"_root": parsed}
        except ValueError:
            body = None

        return HttpResult(
            ok=response.is_success,
            status=response.status_code,
            body=body,
            text=self.redact(text[:20000]),
            headers={k.lower(): v for k, v in response.headers.items()},
            latency_ms=latency_ms,
            error=None if response.is_success else self.redact(
                (self.wire.parse_error(body) if body else None) or f"HTTP {response.status_code}"
            ),
            redirect_to=response.headers.get("location"),
            tls=self.tls,
        )

    def chat(self, body: dict[str, Any]) -> HttpResult:
        return self._request("POST", self.wire.chat_path, json_body=body)

    def chat_with_key(self, body: dict[str, Any], key: str) -> HttpResult:
        return self._request("POST", self.wire.chat_path, json_body=body, key_override=key)

    def models(self) -> HttpResult:
        return self._request("GET", self.wire.models_path)

    def get(self, path: str, *, authed: bool = False) -> HttpResult:
        return self._request("GET", path, authed=authed)

    def malformed_chat(self) -> HttpResult:
        """Deliberately invalid body, to inspect the error envelope shape."""
        return self._request("POST", self.wire.chat_path, json_body={"model": "", "messages": "not-a-list"})
