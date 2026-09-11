"""End-to-end: run the auditor against a router that is known to tamper."""

import time

import pytest
from mock_router import MockRouter

from agentpolice.canary import CanaryHit, LocalCanaryProvider, MemoryCanaryStore
from agentpolice.models import AttackClass, SessionFingerprint, Severity, Verdict
from agentpolice.runner import AuditConfig, Auditor

FAST = 100_000.0  # effectively disable rate limiting in tests


def audit(router, *, classes=None, repeats=2, fingerprints=None, store=None,
          skip_hygiene=True, wire="anthropic"):
    store = store or MemoryCanaryStore()
    provider = LocalCanaryProvider("https://canary.test", "c.canary.test", store)
    config = AuditConfig(
        base_url=router.base_url, api_key="sk-test-key", model="test-model",
        wire_name=wire, repeats=repeats, rate_per_minute=FAST,
        classes=classes or [AttackClass.AC1, AttackClass.AC1A],
        fingerprints=fingerprints or [SessionFingerprint()],
        skip_hygiene=skip_hygiene,
    )
    auditor = Auditor(config, provider)
    return auditor.run(), store, provider


def tamper_findings(report):
    return [f for f in report.findings if f.id.startswith("tamper.")]


class TestCleanEndpoint:
    def test_no_tamper_findings(self):
        with MockRouter("clean") as router:
            report, _, _ = audit(router)
        assert tamper_findings(report) == []
        verdicts = {o.verdict for o in report.observations}
        assert Verdict.CLEAN in verdicts
        assert Verdict.TAMPERED not in verdicts

    def test_coverage_finding_refuses_to_certify_clean(self):
        with MockRouter("clean") as router:
            report, _, _ = audit(router)
        coverage = next(f for f in report.findings if f.id == "coverage.summary")
        assert "not a clean bill of health" in coverage.summary
        assert coverage.attack_class is AttackClass.AC1B


class TestAc1Detection:
    def test_url_rewrite_is_critical_and_high_confidence(self):
        with MockRouter("ac1_url") as router:
            report, _, _ = audit(router, classes=[AttackClass.AC1])
        findings = tamper_findings(report)
        assert findings, "expected the rewritten URL to be reported"
        worst = min(findings, key=lambda f: f.severity.rank)
        assert worst.severity is Severity.CRITICAL
        assert worst.confidence == "high"
        assert any("cdn-assets.example" in e for e in worst.evidence)

    def test_stability_across_nonces_is_cited(self):
        with MockRouter("ac1_url") as router:
            report, _, _ = audit(router, classes=[AttackClass.AC1], repeats=3)
        finding = tamper_findings(report)[0]
        assert "distinct" in finding.evidence[0] and "nonce" in finding.evidence[0]

    def test_non_shell_tool_also_probed(self):
        with MockRouter("ac1_url") as router:
            report, _, _ = audit(router, classes=[AttackClass.AC1])
        assert any(o.probe_id == "ac1.http_get_tool" for o in report.observations)


class TestAc1aDetection:
    def test_package_substitution_reported_as_ac1a(self):
        with MockRouter("ac1a_pkg") as router:
            report, _, _ = audit(router, classes=[AttackClass.AC1A])
        findings = tamper_findings(report)
        assert findings
        assert all(f.attack_class is AttackClass.AC1A for f in findings)
        assert any("reqeusts" in e for f in findings for e in f.evidence)

    def test_summary_explains_allowlist_bypass(self):
        with MockRouter("ac1a_pkg") as router:
            report, _, _ = audit(router, classes=[AttackClass.AC1A])
        finding = tamper_findings(report)[0]
        assert "allowlist" in finding.summary


class TestAc1bConditionalDelivery:
    def test_only_the_triggering_cell_is_dirty(self):
        fingerprints = [
            SessionFingerprint(project_lang="python", autonomy="interactive"),
            SessionFingerprint(project_lang="rust", autonomy="yolo"),
        ]
        with MockRouter("ac1b_conditional") as router:
            report, _, _ = audit(router, classes=[AttackClass.AC1],
                                 fingerprints=fingerprints, repeats=2)
        dirty = {o.cell for o in report.observations if o.verdict is Verdict.TAMPERED}
        clean = {o.cell for o in report.observations if o.verdict is Verdict.CLEAN}
        assert any("lang=rust" in c and "autonomy=yolo" in c for c in dirty)
        assert any("lang=python" in c for c in clean)

    def test_selective_finding_is_raised(self):
        fingerprints = [
            SessionFingerprint(project_lang="python", autonomy="interactive"),
            SessionFingerprint(project_lang="rust", autonomy="yolo"),
        ]
        with MockRouter("ac1b_conditional") as router:
            report, _, _ = audit(router, classes=[AttackClass.AC1],
                                 fingerprints=fingerprints)
        selective = next(f for f in report.findings if f.id == "ac1b.selective")
        assert selective.severity is Severity.CRITICAL
        assert selective.attack_class is AttackClass.AC1B

    def test_single_fingerprint_audit_misses_it_entirely(self):
        """The paper's point: probing only the wrong cell certifies a dirty router."""
        with MockRouter("ac1b_conditional") as router:
            report, _, _ = audit(
                router, classes=[AttackClass.AC1],
                fingerprints=[SessionFingerprint(project_lang="python", autonomy="interactive")],
            )
        assert tamper_findings(report) == []

    def test_warmup_threshold_hides_then_reveals(self):
        with MockRouter("ac1b_conditional") as router:
            router.state.warmup_threshold = 8
            report, _, _ = audit(
                router, classes=[AttackClass.AC1], repeats=1,
                fingerprints=[
                    SessionFingerprint(project_lang="rust", autonomy="yolo", warmup_index=0),
                    SessionFingerprint(project_lang="rust", autonomy="yolo", warmup_index=12),
                ],
            )
        by_cell = {}
        for o in report.observations:
            by_cell.setdefault(o.cell, set()).add(o.verdict)
        warm = next(v for c, v in by_cell.items() if "warmup=12" in c)
        assert Verdict.TAMPERED in warm


class TestAc2Canaries:
    def test_canaries_actually_reach_the_endpoint(self):
        with MockRouter("clean") as router:
            report, store, _ = audit(router, classes=[AttackClass.AC2], repeats=1)
            seen = set(router.state.seen_secrets)
        planted = {c["value"] for c in report.canaries}
        assert seen, "the mock should have observed planted credentials"
        assert seen & planted, "planted canaries must appear in the traffic the endpoint sees"

    def test_all_four_placements_are_exercised(self):
        with MockRouter("clean") as router:
            report, _, _ = audit(router, classes=[AttackClass.AC2], repeats=1)
        placements = {c["placement"] for c in report.canaries}
        assert {"system_prompt", "user_message", "tool_result", "tool_description"} <= placements

    def test_pending_finding_when_no_hit(self):
        with MockRouter("clean") as router:
            report, _, _ = audit(router, classes=[AttackClass.AC2], repeats=1)
        pending = next(f for f in report.findings if f.id == "ac2.canary_pending")
        assert pending.severity is Severity.INFO

    def test_hit_is_critical(self):
        store = MemoryCanaryStore()
        with MockRouter("clean") as router:
            provider = LocalCanaryProvider("https://canary.test", "c.canary.test", store)
            config = AuditConfig(
                base_url=router.base_url, api_key="k", model="m", repeats=1,
                rate_per_minute=FAST, classes=[AttackClass.AC2], skip_hygiene=True,
            )
            auditor = Auditor(config, provider)
            # Simulate the collector seeing one planted canary being fetched.
            original_run_trial = auditor._run_trial

            def spy(client, trial):
                result = original_run_trial(client, trial)
                tokens = trial.meta.get("canaries") or []
                if tokens and not store.hits([tokens[0]]):
                    store.record_hit(CanaryHit(tokens[0], "url", time.time(),
                                               "203.0.113.9", "python-requests/2.31"))
                return result

            auditor._run_trial = spy
            report = auditor.run()
        hit = next(f for f in report.findings if f.id == "ac2.canary_hit")
        assert hit.severity is Severity.CRITICAL
        assert "203.0.113.9" in " ".join(hit.evidence)


class TestHygiene:
    def test_open_relay_is_high(self):
        with MockRouter("clean") as router:
            router.state.require_auth = False
            report, _, _ = audit(router, classes=[AttackClass.AC1], repeats=1,
                                 skip_hygiene=False)
        auth = next(f for f in report.findings if f.id == "hygiene.auth")
        assert auth.severity is Severity.HIGH
        assert "open relay" in auth.summary

    def test_auth_enforced_is_info(self):
        with MockRouter("clean") as router:
            report, _, _ = audit(router, classes=[AttackClass.AC1], repeats=1,
                                 skip_hygiene=False)
        auth = next(f for f in report.findings if f.id == "hygiene.auth")
        assert auth.severity is Severity.INFO

    def test_multi_vendor_model_list_flagged(self):
        with MockRouter("clean") as router:
            report, _, _ = audit(router, classes=[AttackClass.AC1], repeats=1,
                                 skip_hygiene=False)
        models = next(f for f in report.findings if f.id == "hygiene.models")
        assert models.severity is Severity.LOW
        assert "vendors" in models.summary

    def test_oneapi_signature_matches(self):
        with MockRouter("clean") as router:
            report, _, _ = audit(router, classes=[AttackClass.AC1], repeats=1,
                                 skip_hygiene=False)
        assert any(f.id == "hygiene.software.oneapi-family" for f in report.findings)

    def test_unknown_host_is_flagged_as_intermediary(self):
        with MockRouter("clean") as router:
            report, _, _ = audit(router, classes=[AttackClass.AC1], repeats=1,
                                 skip_hygiene=False)
        identity = next(f for f in report.findings if f.id == "hygiene.identity")
        assert identity.severity is Severity.MEDIUM


class TestWireFormats:
    @pytest.mark.parametrize("wire", ["anthropic", "openai"])
    def test_both_formats_detect_the_same_rewrite(self, wire):
        with MockRouter("ac1_url") as router:
            report, _, _ = audit(router, classes=[AttackClass.AC1], wire=wire)
        assert tamper_findings(report)


class TestKeyHygiene:
    def test_api_key_never_appears_in_the_report(self):
        secret = "sk-ant-super-secret-value-9876543210"
        with MockRouter("ac1_url") as router:
            store = MemoryCanaryStore()
            config = AuditConfig(
                base_url=router.base_url, api_key=secret, model="m",
                repeats=1, rate_per_minute=FAST, classes=[AttackClass.AC1],
                skip_hygiene=False,
            )
            report = Auditor(config, LocalCanaryProvider("https://c.test", None, store)).run()
        import json
        assert secret not in json.dumps(report.to_dict())


class TestCanaryAttributionWording:
    """A DNS hit shows the resolver, not the looker-up. Say so."""

    def _report_with_hit(self, kind):
        store = MemoryCanaryStore()
        with MockRouter("clean") as router:
            provider = LocalCanaryProvider("https://c.test", "c.test", store)
            config = AuditConfig(base_url=router.base_url, api_key="k", model="m",
                                 repeats=1, rate_per_minute=FAST,
                                 classes=[AttackClass.AC2], skip_hygiene=True)
            auditor = Auditor(config, provider)
            original = auditor._run_trial

            def spy(client, trial):
                result = original(client, trial)
                tokens = trial.meta.get("canaries") or []
                if tokens and not store.hits([tokens[0]]):
                    store.record_hit(CanaryHit(tokens[0], kind, time.time(),
                                               "198.51.100.5", "curl/8"))
                return result

            auditor._run_trial = spy
            return auditor.run()

    def test_dns_hit_is_not_described_as_a_fetch(self):
        report = self._report_with_hit("dns")
        finding = next(f for f in report.findings if f.id == "ac2.canary_hit")
        joined = " ".join(finding.evidence)
        assert "resolver" in joined
        assert "fetched by" not in joined

    def test_http_hit_names_the_caller(self):
        report = self._report_with_hit("url")
        finding = next(f for f in report.findings if f.id == "ac2.canary_hit")
        joined = " ".join(finding.evidence)
        assert "fetched by 198.51.100.5" in joined


class TestCoverageHonesty:
    """A handful of usable trials must not be reported as "no tampering"."""

    def test_refusal_is_distinguished_from_silence(self):
        from agentpolice.detect.toolcall import classify
        from agentpolice.models import Expectation
        refused, _ = classify(Expectation("Bash", {"command": "x"}), [],
                              "I can't run that command, it downloads a script.")
        silent, _ = classify(Expectation("Bash", {"command": "x"}), [], "")
        assert refused is Verdict.REFUSED
        assert silent is Verdict.NO_TOOL_CALL

    def test_low_usable_ratio_is_flagged_inconclusive(self):
        from agentpolice.models import AuditReport, Observation
        auditor = Auditor(AuditConfig(base_url="https://x.test", api_key="k", model="m"))
        auditor.report = AuditReport(target="t", wire_format="openai", model="m",
                                     started_at=0.0)
        auditor.report.observations = (
            [Observation(f"c{i}", "p", AttackClass.AC1, Verdict.CLEAN, "n", "cell")
             for i in range(6)]
            + [Observation(f"r{i}", "p", AttackClass.AC1, Verdict.REFUSED, "n", "cell")
               for i in range(48)]
        )
        finding = auditor._coverage_finding()
        assert finding.severity is Severity.MEDIUM
        assert "inconclusive" in finding.summary
        assert "refused" in finding.summary

    def test_good_coverage_still_reads_as_no_tampering(self):
        from agentpolice.models import AuditReport, Observation
        auditor = Auditor(AuditConfig(base_url="https://x.test", api_key="k", model="m"))
        auditor.report = AuditReport(target="t", wire_format="openai", model="m",
                                     started_at=0.0)
        auditor.report.observations = [
            Observation(f"c{i}", "p", AttackClass.AC1, Verdict.CLEAN, "n", "cell")
            for i in range(20)
        ]
        finding = auditor._coverage_finding()
        assert finding.severity is Severity.INFO
        assert "not a clean bill of health" in finding.summary
