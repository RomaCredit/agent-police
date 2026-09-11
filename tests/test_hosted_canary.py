"""Canaries planted by a CLI run must be visible to a remote collector.

This closes a gap found while auditing a real endpoint: the CLI printed canary
URLs pointing at the hosted collector, but registered the tokens only in its
own local SQLite. The collector drops callbacks for tokens it has never seen,
so the entire AC-2 path was silently inert while reporting "45 canaries
planted, check back later".
"""

import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentpolice.canary import HostedCanaryProvider
from agentpolice.cli import collector_is_remote
from agentpolice.server import app as app_module


@pytest.fixture
def db_path():
    return str(Path(tempfile.mkdtemp()) / "canaries.db")


@pytest.fixture
def client(db_path):
    return TestClient(app_module.create_app(
        canary_db=db_path, canary_base="http://testserver", canary_dns="c.test"))


class TestRemoteDetection:
    @pytest.mark.parametrize("base", [
        "https://security.romaapi.com",
        "http://collector.example.org:8080",
    ])
    def test_remote_bases(self, base):
        assert collector_is_remote(base)

    @pytest.mark.parametrize("base", [
        "", None, "http://127.0.0.1:8099", "http://localhost:8080", "https://localhost",
    ])
    def test_local_bases(self, base):
        assert not collector_is_remote(base)


class TestRegistrationEndpoint:
    def test_accepts_a_real_provider_payload(self, client):
        """Register exactly what HostedCanaryProvider sends, not a hand-built dict.

        A dict[str, str] schema here rejected every real payload with a 422,
        because Canary.to_dict() carries a bool and a float. Tests that built
        string-only dicts passed anyway - they were exercising the fixture
        rather than the integration.
        """
        provider = HostedCanaryProvider("http://testserver", "c.test", "cli-realpayload")
        planted = [provider.issue(kind, "user_message") for kind in ("url", "dns")]
        res = client.post("/api/canary/register", json={
            "audit_id": "cli-realpayload",
            "canaries": [c.to_dict() for c in planted],
        })
        assert res.status_code == 200, res.text
        assert res.json()["registered"] == 2

        client.get(f"/c/{planted[0].token}")
        assert len(client.get("/api/canary/cli-realpayload").json()["hits"]) == 1

    def test_registered_token_records_a_hit(self, client):
        token = "abcdefghijklmnopqrst"
        res = client.post("/api/canary/register", json={
            "audit_id": "cli-deadbeef0001",
            "canaries": [{"token": token, "kind": "url", "value": "u",
                          "placement": "user_message"}],
        })
        assert res.status_code == 200
        assert res.json()["registered"] == 1

        client.get(f"/c/{token}", headers={"user-agent": "curl/8"})
        status = client.get("/api/canary/cli-deadbeef0001").json()
        assert status["planted"] == 1
        assert len(status["hits"]) == 1
        assert status["hits"][0]["user_agent"] == "curl/8"

    def test_unregistered_token_is_still_dropped(self, client):
        client.get("/c/zzzzzzzzzzzzzzzzzzzz")
        assert client.get("/api/canary/cli-nothing").json()["hits"] == []

    def test_malformed_tokens_are_rejected(self, client):
        res = client.post("/api/canary/register", json={
            "audit_id": "cli-deadbeef0002",
            "canaries": [
                {"token": "SHORT", "kind": "url"},
                {"token": "has-a-dash-in-it-xyz", "kind": "url"},
                {"token": "abcdefghijklmnopqrst", "kind": "aws"},
                {"token": "bbcdefghijklmnopqrst", "kind": "url"},
            ],
        })
        body = res.json()
        assert body["registered"] == 1
        assert body["rejected"] == 3

    def test_decoy_kinds_are_not_registered(self, client):
        res = client.post("/api/canary/register", json={
            "audit_id": "cli-deadbeef0003",
            "canaries": [{"token": "ccdefghijklmnopqrstu", "kind": "eth"}],
        })
        assert res.json()["registered"] == 0

    def test_audit_id_is_constrained(self, client):
        res = client.post("/api/canary/register", json={
            "audit_id": "../../etc/passwd",
            "canaries": [{"token": "ddefghijklmnopqrstuv", "kind": "url"}],
        })
        assert res.status_code == 422


class TestHostedProvider:
    def test_url_canary_points_at_the_collector(self):
        p = HostedCanaryProvider("https://collector.test", "c.test", "cli-1")
        c = p.issue("url", "user_message")
        assert c.observable and c.value.startswith("https://collector.test/c/")
        assert c.token in c.value

    def test_dns_canary_uses_the_zone(self):
        p = HostedCanaryProvider("https://collector.test", "c.test", "cli-1")
        c = p.issue("dns", "probe_payload")
        assert c.observable and c.value.endswith(".c.test")

    def test_dns_falls_back_to_url_without_a_zone(self):
        p = HostedCanaryProvider("https://collector.test", None, "cli-1")
        c = p.issue("dns", "probe_payload")
        assert c.kind == "url" and c.observable

    def test_decoys_are_not_queued_for_registration(self):
        p = HostedCanaryProvider("https://collector.test", "c.test", "cli-1")
        c = p.issue("aws", "user_message")
        assert not c.observable
        assert c.value.startswith("AKIA")
        assert p._pending == []

    def test_unreachable_collector_is_reported_not_raised(self):
        p = HostedCanaryProvider("https://collector.invalid", "c.invalid", "cli-1")
        p.issue("url", "user_message")
        p.flush()  # must not raise
        assert p.error is not None
        assert p.registered == 0

    def test_hits_on_an_unreachable_collector_return_empty(self):
        p = HostedCanaryProvider("https://collector.invalid", None, "cli-1")
        assert p.hits(["abcdefghijklmnopqrst"]) == []
        assert p.error is not None


class TestRegistrationOrdering:
    """Tokens must reach the collector before the probe that exposes them."""

    def test_flush_happens_before_the_first_request(self):
        import sys

        sys.path.insert(0, str(Path(__file__).parent))
        from mock_router import MockRouter

        from agentpolice.canary import Canary, CanaryProvider, new_token
        from agentpolice.models import AttackClass
        from agentpolice.runner import AuditConfig, Auditor

        events: list[str] = []

        class RecordingProvider(CanaryProvider):
            def issue(self, kind, placement):
                token = new_token()
                events.append(f"issue:{token[:6]}")
                return Canary(token, "url", f"https://c.test/c/{token}",
                              placement, True)

            def hits(self, tokens):
                return []

            def flush(self):
                events.append("flush")

        with MockRouter("clean") as router:
            config = AuditConfig(
                base_url=router.base_url, api_key="k", model="m",
                repeats=1, rate_per_minute=100_000.0,
                classes=[AttackClass.AC2], skip_hygiene=True,
            )
            auditor = Auditor(config, RecordingProvider())
            original = auditor._run_trial

            def spy(client, trial):
                events.append("request")
                return original(client, trial)

            auditor._run_trial = spy
            auditor.run()

        assert "flush" in events and "request" in events
        assert events.index("flush") < events.index("request")
        # And every issue in the first batch precedes that flush.
        assert events[0].startswith("issue:")
