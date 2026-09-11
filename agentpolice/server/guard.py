"""Target validation for the hosted service.

The service fetches a URL supplied by a stranger, which makes it an SSRF
primitive unless the target is constrained. Only public, named hosts over
https are allowed: no loopback, no private ranges, no link-local (which is
where cloud metadata services live), and no bare IP addresses.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

ALLOWED_SCHEMES = {"https"}
ALLOWED_PORTS = {None, 443, 8443}

BLOCKED_HOST_SUFFIXES = (
    ".local", ".internal", ".localdomain", ".cluster.local",
)
BLOCKED_HOSTNAMES = {"localhost", "metadata", "metadata.google.internal", "instance-data"}


class TargetRejected(ValueError):
    """The supplied endpoint may not be probed by the hosted service."""


def _is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
        or ip.is_reserved or ip.is_unspecified
    )


def assert_public_target(base_url: str, *, allow_http: bool = False) -> str:
    """Validate *base_url* and return its hostname, or raise TargetRejected."""
    raw = (base_url or "").strip()
    if not raw:
        raise TargetRejected("Enter an endpoint URL.")
    if "://" not in raw:
        raw = "https://" + raw

    parts = urlsplit(raw)
    schemes = ALLOWED_SCHEMES | ({"http"} if allow_http else set())
    if parts.scheme not in schemes:
        raise TargetRejected(f"Only {'/'.join(sorted(schemes))} endpoints can be probed.")

    host = (parts.hostname or "").lower()
    if not host:
        raise TargetRejected("The URL has no hostname.")
    if parts.port not in ALLOWED_PORTS and not allow_http:
        raise TargetRejected(f"Port {parts.port} is not allowed; use 443.")

    if host in BLOCKED_HOSTNAMES or any(host.endswith(s) for s in BLOCKED_HOST_SUFFIXES):
        raise TargetRejected("Internal hostnames cannot be probed by the hosted service.")

    # A bare IP tells us nothing about who operates the endpoint, and is the
    # usual shape of an SSRF attempt.
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise TargetRejected(
            "Give a hostname rather than an IP address. Run the CLI locally to probe by IP."
        )

    try:
        infos = socket.getaddrinfo(host, parts.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise TargetRejected(f"{host} does not resolve ({exc.strerror or exc}).") from None

    addresses = {info[4][0] for info in infos}
    if not addresses:
        raise TargetRejected(f"{host} does not resolve to any address.")
    for address in addresses:
        if not _is_public(address):
            raise TargetRejected(
                f"{host} resolves to a non-public address ({address}); the hosted service "
                "will not probe internal networks. Run the CLI locally instead."
            )
    return host
