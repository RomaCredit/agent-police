"""Tests for the DNS canary collector."""

import socket
import struct
import tempfile
import time
from pathlib import Path

import pytest

from agentpolice.canary import Canary
from agentpolice.server.dnscanary import (
    QTYPE_A,
    RCODE_NXDOMAIN,
    RCODE_OK,
    RCODE_REFUSED,
    parse_question,
    start_dns_collector,
)
from agentpolice.store import SqliteCanaryStore

ZONE = "c.test"


def encode_query(name: str, qtype: int = QTYPE_A) -> bytes:
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    labels = b"".join(
        bytes([len(part)]) + part.encode() for part in name.split(".")
    ) + b"\x00"
    return header + labels + struct.pack("!HH", qtype, 1)


@pytest.fixture
def collector():
    store = SqliteCanaryStore(str(Path(tempfile.mkdtemp()) / "c.db"))
    server = start_dns_collector(zone=ZONE, store=store, host="127.0.0.1",
                                 port=0, answer_a="192.0.2.7")
    yield server, store
    server.shutdown()
    server.server_close()


def ask(server, query: bytes) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(query, server.server_address)
        return sock.recv(512)
    finally:
        sock.close()


def rcode(response: bytes) -> int:
    return struct.unpack("!H", response[2:4])[0] & 0x000F


class TestParsing:
    def test_parses_a_query(self):
        name, qtype, qclass, end = parse_question(encode_query("abc.c.test"))
        assert name == "abc.c.test" and qtype == QTYPE_A and qclass == 1

    def test_rejects_truncated(self):
        assert parse_question(b"\x00\x01") is None

    def test_rejects_compression_pointer_in_question(self):
        header = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
        assert parse_question(header + b"\xc0\x0c" + struct.pack("!HH", 1, 1)) is None


class TestCollector:
    def test_known_token_is_recorded_and_answered(self, collector):
        server, store = collector
        token = "tok" + "c" * 17
        store.register(Canary(token, "dns", f"{token}.{ZONE}", "user_message", True), "aud1")

        response = ask(server, encode_query(f"{token}.{ZONE}"))
        assert rcode(response) == RCODE_OK

        for _ in range(20):
            hits = store.hits_for_audit("aud1")
            if hits:
                break
            time.sleep(0.05)
        assert len(hits) == 1
        assert hits[0].kind == "dns" and hits[0].source_ip == "127.0.0.1"

    def test_unknown_token_is_nxdomain_and_unrecorded(self, collector):
        server, store = collector
        response = ask(server, encode_query(f"nosuchtoken.{ZONE}"))
        assert rcode(response) == RCODE_NXDOMAIN
        assert store.hits(["nosuchtoken"]) == []

    def test_out_of_zone_query_is_refused(self, collector):
        server, _ = collector
        assert rcode(ask(server, encode_query("example.com"))) == RCODE_REFUSED

    def test_subdomain_of_token_still_resolves_the_token(self, collector):
        server, store = collector
        token = "tok" + "d" * 17
        store.register(Canary(token, "dns", "", "tool_result", True), "aud2")
        ask(server, encode_query(f"www.{token}.{ZONE}"))
        for _ in range(20):
            if store.hits_for_audit("aud2"):
                break
            time.sleep(0.05)
        assert store.hits_for_audit("aud2")


class TestZoneApex:
    def test_apex_is_nodata_not_nxdomain(self, collector):
        """RFC 8020: NXDOMAIN at the apex would deny the whole subtree."""
        server, _ = collector
        response = ask(server, encode_query(ZONE))
        assert rcode(response) == RCODE_OK
        ancount = struct.unpack("!H", response[6:8])[0]
        assert ancount == 0, "apex must answer NODATA, not a record"

    def test_tokens_still_resolve_after_an_apex_query(self, collector):
        server, store = collector
        token = "tok" + "h" * 17
        store.register(Canary(token, "dns", "", "user_message", True), "aud3")
        ask(server, encode_query(ZONE))
        assert rcode(ask(server, encode_query(f"{token}.{ZONE}"))) == RCODE_OK


class TestApexNs:
    def test_ns_query_at_apex_is_answered(self):
        store = SqliteCanaryStore(str(Path(tempfile.mkdtemp()) / "c.db"))
        server = start_dns_collector(zone=ZONE, store=store, host="127.0.0.1", port=0,
                                     answer_a="192.0.2.7", nameserver="ns.example.test")
        try:
            response = ask(server, encode_query(ZONE, qtype=2))
            assert rcode(response) == RCODE_OK
            assert struct.unpack("!H", response[6:8])[0] == 1
            assert b"\x02ns\x07example\x04test\x00" in response
        finally:
            server.shutdown()
            server.server_close()

    def test_apex_without_nameserver_still_nodata(self, collector):
        server, _ = collector
        response = ask(server, encode_query(ZONE, qtype=2))
        assert rcode(response) == RCODE_OK
        assert struct.unpack("!H", response[6:8])[0] == 0


class TestWireFormat:
    """Guard the whole packet, not just the fields a given assertion reads.

    The header was short by one field for a while and every existing test still
    passed, because rcode and ancount sit before the missing ARCOUNT and so
    kept their offsets. Only re-parsing the response caught it.
    """

    def test_response_header_is_twelve_bytes_and_question_echoes(self, collector):
        server, store = collector
        token = "tok" + "i" * 17
        store.register(Canary(token, "dns", "", "user_message", True), "aud-wire")
        name = f"{token}.{ZONE}"
        response = ask(server, encode_query(name))

        counts = struct.unpack("!HHHHHH", response[:12])
        assert counts[2] == 1, "QDCOUNT"
        assert counts[3] == 1, "ANCOUNT"

        echoed = parse_question(response)
        assert echoed is not None, "question section must be parseable"
        assert echoed[0] == name
        assert echoed[1] == QTYPE_A

    def test_answer_rdata_is_the_configured_address(self, collector):
        server, store = collector
        token = "tok" + "j" * 17
        store.register(Canary(token, "dns", "", "user_message", True), "aud-rdata")
        response = ask(server, encode_query(f"{token}.{ZONE}"))
        _, _, _, end = parse_question(response)
        rdlength = struct.unpack("!H", response[end + 10:end + 12])[0]
        assert rdlength == 4
        assert socket.inet_ntoa(response[end + 12:end + 16]) == "192.0.2.7"

    def test_transaction_id_is_echoed(self, collector):
        server, _ = collector
        response = ask(server, encode_query(f"unknown.{ZONE}"))
        assert response[:2] == struct.pack("!H", 0x1234)

    def test_nxdomain_response_is_also_well_formed(self, collector):
        server, _ = collector
        response = ask(server, encode_query(f"unknown.{ZONE}"))
        assert rcode(response) == RCODE_NXDOMAIN
        echoed = parse_question(response)
        assert echoed is not None and echoed[0] == f"unknown.{ZONE}"
