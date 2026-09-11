"""DNS canary collector.

An HTTP canary only fires when something actually fetches the URL. Plenty of
credential scanners resolve a hostname first - to check it is live, or simply
as a side effect of a connection attempt - and never complete the request. A
DNS canary catches those.

Requires the canary zone to be delegated to this host with an NS record, and
UDP/53 to be reachable. Without delegation nothing breaks: LocalCanaryProvider
falls back to HTTP canaries.

Only the minimum of DNS is implemented: A and AAAA queries for
<token>.<zone> are answered, and the lookup is recorded. Anything else gets
NXDOMAIN or REFUSED.
"""

from __future__ import annotations

import socket
import socketserver
import struct
import threading
import time

from ..canary import CanaryHit
from ..store import SqliteCanaryStore

QTYPE_A = 1
QTYPE_AAAA = 28
QTYPE_NS = 2
QCLASS_IN = 1

RCODE_OK = 0
RCODE_NXDOMAIN = 3
RCODE_REFUSED = 5


def parse_question(data: bytes) -> tuple[str, int, int, int] | None:
    """Return (qname, qtype, qclass, end_offset) for the first question."""
    if len(data) < 12:
        return None
    qdcount = struct.unpack("!H", data[4:6])[0]
    if qdcount < 1:
        return None

    labels: list[str] = []
    offset = 12
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0:  # compression pointers are not valid in a question
            return None
        offset += 1
        if offset + length > len(data):
            return None
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    if offset + 4 > len(data):
        return None
    qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
    return ".".join(labels).lower(), qtype, qclass, offset + 4


def encode_name(name: str) -> bytes:
    """Wire-format a domain name as length-prefixed labels."""
    out = b""
    for label in name.strip(".").split("."):
        raw = label.encode("idna" if any(ord(c) > 127 for c in label) else "ascii")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_response(query: bytes, question_end: int, *, rcode: int,
                   answer_ip: str | None, qtype: int, ttl: int = 30,
                   rdata_override: bytes | None = None) -> bytes:
    transaction_id = query[:2]
    question = query[12:question_end]

    answers = b""
    ancount = 0
    rdata = rdata_override
    if rcode == RCODE_OK and rdata is None and answer_ip:
        rdata = (socket.inet_aton(answer_ip) if qtype == QTYPE_A
                 else socket.inet_pton(socket.AF_INET6, answer_ip))
    if rcode == RCODE_OK and rdata:
        answers = (
            b"\xc0\x0c"                                   # pointer to the question name
            + struct.pack("!HHIH", qtype, QCLASS_IN, ttl, len(rdata))
            + rdata
        )
        ancount = 1

    flags = 0x8400 | rcode  # QR + AA
    # ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT - all six, or every byte
    # after the header lands two short and the question section is unparseable.
    header = struct.pack("!HHHHHH", 0, flags, 1, ancount, 0, 0)
    return transaction_id + header[2:] + question + answers


class CanaryResolver(socketserver.BaseRequestHandler):
    zone: str = ""
    store: SqliteCanaryStore | None = None
    answer_a: str | None = None
    answer_aaaa: str | None = None
    nameserver: str | None = None

    def handle(self) -> None:
        data, sock = self.request
        parsed = parse_question(data)
        if parsed is None:
            return
        qname, qtype, qclass, end = parsed

        if qclass != QCLASS_IN or not qname.endswith(self.zone):
            sock.sendto(build_response(data, end, rcode=RCODE_REFUSED,
                                       answer_ip=None, qtype=qtype), self.client_address)
            return

        label = qname[: -len(self.zone)].rstrip(".")
        token = label.split(".")[-1] if label else ""

        if not label and qtype == QTYPE_NS and self.nameserver:
            # Be a well-behaved child zone: answer NS for ourselves, so that
            # `dig NS <zone>` through a recursive resolver confirms the
            # delegation instead of coming back empty.
            sock.sendto(build_response(
                data, end, rcode=RCODE_OK, answer_ip=None, qtype=qtype, ttl=3600,
                rdata_override=encode_name(self.nameserver),
            ), self.client_address)
            return

        if not label:
            # The zone apex. Answering NXDOMAIN here would be actively harmful:
            # under RFC 8020 an NXDOMAIN at c.example asserts that everything
            # below it is empty too, so a compliant resolver would stop asking
            # about the token names that are the entire point of the zone.
            # NOERROR with no answer (NODATA) says "this name exists, just not
            # this type", which leaves the subtree resolvable.
            sock.sendto(build_response(data, end, rcode=RCODE_OK,
                                       answer_ip=None, qtype=qtype), self.client_address)
            return

        recorded = False
        if token and self.store is not None:
            canary = self.store.lookup(token)
            if canary is not None:
                self.store.record_hit(CanaryHit(
                    token=token, kind="dns", at=time.time(),
                    source_ip=self.client_address[0],
                    user_agent=None,
                    detail=f"{qname} type={qtype}",
                ))
                recorded = True

        answer = self.answer_a if qtype == QTYPE_A else (
            self.answer_aaaa if qtype == QTYPE_AAAA else None)
        if recorded and answer:
            response = build_response(data, end, rcode=RCODE_OK,
                                      answer_ip=answer, qtype=qtype)
        else:
            response = build_response(data, end, rcode=RCODE_NXDOMAIN,
                                      answer_ip=None, qtype=qtype)
        sock.sendto(response, self.client_address)


class ThreadedUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_dns_collector(*, zone: str, store: SqliteCanaryStore,
                        host: str = "0.0.0.0", port: int = 53,
                        answer_a: str | None = None,
                        answer_aaaa: str | None = None,
                        nameserver: str | None = None) -> ThreadedUDPServer:
    """Start the collector in a background thread and return the server."""
    handler = type("BoundResolver", (CanaryResolver,), {
        "zone": zone.strip(".").lower(),
        "store": store,
        "answer_a": answer_a,
        "answer_aaaa": answer_aaaa,
        "nameserver": nameserver,
    })
    server = ThreadedUDPServer((host, port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True,
                              name="canary-dns")
    thread.start()
    return server
