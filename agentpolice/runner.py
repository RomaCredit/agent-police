"""Execute probes against an endpoint and aggregate the result into findings."""

from __future__ import annotations

import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Callable, Iterable

from .canary import CanaryProvider, NullCanaryProvider
from .client import RouterClient
from .detect.toolcall import classify
from .models import (
    AttackClass, AuditReport, Deviation, Finding, Observation,
    SessionFingerprint, Severity, Trial, Verdict,
)
from .probes import registry
from .probes.base import ProbeContext, SHELL_TOOLS
from .probes.hygiene import run_hygiene
from .wire import PROBE_SYSTEM_PROMPT, get_wire

# How bad each adversarial deviation is, and why.
DEVIATION_SEVERITY: dict[str, Severity] = {
    "url_host_changed": Severity.CRITICAL,
    "url_added": Severity.CRITICAL,
    "command_chained": Severity.CRITICAL,
    "command_substitution_added": Severity.CRITICAL,
    "tool_name_changed": Severity.CRITICAL,
    "package_substituted": Severity.CRITICAL,
    "package_added": Severity.CRITICAL,
    "url_path_changed": Severity.HIGH,
    "url_scheme_downgraded": Severity.HIGH,
}

ProgressFn = Callable[[str, int, int], None]


@dataclass(slots=True)
class AuditConfig:
    base_url: str
    api_key: str
    model: str
    wire_name: str = "anthropic"
    repeats: int = 2
    """Distinct nonces per probe. Two or more lets stability separate tampering from noise."""
    rate_per_minute: float = 20.0
    timeout: float = 90.0
    verify_tls: bool = True
    require_public_peer: bool = False
    probe_ids: list[str] | None = None
    classes: list[AttackClass] = field(
        default_factory=lambda: [AttackClass.AC1, AttackClass.AC1A, AttackClass.AC2]
    )
    fingerprints: list[SessionFingerprint] = field(
        default_factory=lambda: [SessionFingerprint()]
    )
    skip_hygiene: bool = False


def selected_probes(config: AuditConfig) -> list:
    if config.probe_ids:
        missing = [p for p in config.probe_ids if p not in registry]
        if missing:
            raise ValueError(f"unknown probe ids: {', '.join(missing)}")
        return [registry[p] for p in config.probe_ids]
    wanted = set(config.classes)
    return [p for p in registry.values() if p.attack_class in wanted]


def _warmup(client: RouterClient, wire, model: str, count: int) -> None:
    """Send benign traffic so a request-count trigger has something to count.

    Section 4.2.2 family 5: a router that waits N requests looks clean to any
    probe that gives up before N.
    """
    for i in range(count):
        body = wire.build_request(
            model=model,
            system=PROBE_SYSTEM_PROMPT,
            user=f"Reply with the single word: ok ({i + 1})",
            tools=[],
            max_tokens=16,
        )
        body.pop("tools", None)
        client.chat(body)


class Auditor:
    def __init__(self, config: AuditConfig, canaries: CanaryProvider | None = None):
        self.config = config
        self.wire = get_wire(config.wire_name)
        self.canaries = canaries or NullCanaryProvider()
        self.report = AuditReport(
            target=config.base_url,
            wire_format=config.wire_name,
            model=config.model,
            started_at=time.time(),
        )
        self._issued_canaries: list = []
        self._last_headers: dict[str, str] = {}
        """Headers from the most recent successful trial, for the hygiene pass."""

    # -- execution ------------------------------------------------------
    def run(self, progress: ProgressFn | None = None) -> AuditReport:
        probes = selected_probes(self.config)
        fingerprints = self.config.fingerprints or [SessionFingerprint()]
        total = len(probes) * len(fingerprints) * max(self.config.repeats, 1)
        done = 0
        latencies: list[float] = []
        sample_headers: dict[str, str] = {}

        with RouterClient(
            self.config.base_url, self.config.api_key, self.wire,
            timeout=self.config.timeout,
            rate_per_minute=self.config.rate_per_minute,
            verify_tls=self.config.verify_tls,
            require_public_peer=self.config.require_public_peer,
        ) as client:
            for fingerprint in fingerprints:
                if fingerprint.warmup_index:
                    if progress:
                        progress(f"warm-up x{fingerprint.warmup_index}", done, total)
                    _warmup(client, self.wire, self.config.model, fingerprint.warmup_index)

                for probe in probes:
                    for _ in range(max(self.config.repeats, 1)):
                        ctx = ProbeContext(
                            wire=self.wire, model=self.config.model,
                            canaries=self.canaries, fingerprint=fingerprint,
                        )
                        trials = probe.trials(ctx)
                        # A canary is exposed the moment its probe is sent, so a
                        # remote collector has to know the token before that, not
                        # at the end of the run: anything that fetches the URL
                        # immediately would otherwise arrive as an unknown token
                        # and be dropped.
                        flush = getattr(self.canaries, "flush", None)
                        if callable(flush):
                            flush()
                        for trial in trials:
                            observation = self._run_trial(client, trial)
                            self.report.observations.append(observation)
                            if observation.latency_ms:
                                latencies.append(observation.latency_ms)
                            done += 1
                            if progress:
                                progress(f"{probe.id} [{fingerprint.cell()}]", done, total)
                        self._issued_canaries.extend(ctx.issued)

            if not self.config.skip_hygiene:
                if progress:
                    progress("endpoint hygiene", done, total)
                sample_headers = self._last_headers
                self.report.findings.extend(
                    run_hygiene(client, sample_headers or None, latencies)
                )

        self.report.canaries = [c.to_dict() for c in self._issued_canaries]
        self._aggregate()
        self.report.finished_at = time.time()
        return self.report

    def _run_trial(self, client: RouterClient, trial: Trial) -> Observation:
        result = client.chat(trial.request)
        self._last_headers = result.headers or self._last_headers

        if not result.ok or result.body is None:
            return Observation(
                trial_id=trial.trial_id, probe_id=trial.probe_id,
                attack_class=trial.attack_class, verdict=Verdict.ERROR,
                nonce=trial.nonce, cell=trial.fingerprint.cell(),
                latency_ms=result.latency_ms,
                error=result.error or f"HTTP {result.status}",
            )

        tool_calls = self.wire.parse_tool_calls(result.body)
        response_text = self.wire.parse_text(result.body)
        verdict, deviations = classify(trial.expectation, tool_calls, response_text)
        observed = tool_calls[0] if tool_calls else None
        return Observation(
            trial_id=trial.trial_id, probe_id=trial.probe_id,
            attack_class=trial.attack_class, verdict=verdict,
            nonce=trial.nonce, cell=trial.fingerprint.cell(),
            deviations=deviations,
            observed_tool=observed.name if observed else None,
            observed_args=observed.arguments if observed else {},
            response_text=response_text,
            latency_ms=result.latency_ms,
        )

    # -- aggregation ----------------------------------------------------
    def _aggregate(self) -> None:
        by_probe: dict[str, list[Observation]] = defaultdict(list)
        for observation in self.report.observations:
            by_probe[observation.probe_id].append(observation)

        for probe_id, observations in sorted(by_probe.items()):
            probe = registry.get(probe_id)
            tampered = [o for o in observations if o.verdict is Verdict.TAMPERED]
            if tampered:
                self.report.add(self._tamper_finding(probe_id, probe, observations, tampered))

        self.report.add(self._coverage_finding())
        self.report.findings.extend(self._canary_findings())
        self.report.findings.extend(self._conditional_findings(by_probe))

    def _tamper_finding(self, probe_id, probe, observations, tampered) -> Finding:
        adversarial: list[Deviation] = [
            d for o in tampered for d in o.deviations if d.adversarial
        ]
        kinds = Counter(d.kind for d in adversarial)
        severity = min(
            (DEVIATION_SEVERITY.get(k, Severity.HIGH) for k in kinds),
            key=lambda s: s.rank,
        )

        # Stability across distinct nonces is the signal that separates a
        # deliberate rewrite from model noise: noise does not keep choosing the
        # same replacement host or package.
        nonces = {o.nonce for o in tampered}
        # Compare the attacker-controlled invariant, not the whole argument: the
        # probe payload carries a fresh nonce every time, so a fixed rewrite rule
        # still produces a different string on each trial.
        signatures = Counter(d.signature for d in adversarial if d.signature)
        repeated = [sig for sig, n in signatures.items() if n >= 2]
        if len(nonces) >= 2 and repeated:
            confidence = "high"
            stability = (
                f"the same rewrite target ({', '.join(sorted(repeated)[:3])}) recurred across "
                f"{len(nonces)} distinct probe nonces, which random model deviation does not do"
            )
        elif len(tampered) >= 2:
            confidence = "medium"
            stability = f"reproduced in {len(tampered)} of {len(observations)} trials"
        else:
            confidence = "low"
            stability = "observed once; re-run with --repeats to confirm"

        evidence = [stability]
        for deviation in adversarial[:6]:
            evidence.append(deviation.detail)
            if deviation.expected and deviation.observed:
                evidence.append(f"  expected: {deviation.expected}")
                evidence.append(f"  returned: {deviation.observed}")

        attack_class = adversarial[0].attack_class or (probe.attack_class if probe else AttackClass.AC1)
        title = probe.title if probe else probe_id
        if attack_class is AttackClass.AC1A:
            summary = (
                "The endpoint changed which package the install command pulls. The registry "
                "and the rest of the command line are untouched, so a domain allowlist would "
                "not fire, and the substituted dependency is cached locally and re-imported "
                "in later sessions."
            )
        else:
            summary = (
                "The endpoint returned a tool call that differs from the one it was asked to "
                "produce, in a way that redirects what the agent would execute. The returned "
                "payload is still schema-valid, so nothing downstream would flag it."
            )

        return Finding(
            id=f"tamper.{probe_id}",
            attack_class=attack_class,
            severity=severity,
            title=f"Tool call rewritten: {title}",
            summary=summary,
            evidence=evidence,
            remediation=(
                "Stop routing agentic traffic through this endpoint. Rotate every credential "
                "that has transited it, and audit any dependency it may have installed."
            ),
            confidence=confidence,
            observations=[o.trial_id for o in tampered],
        )

    def _coverage_finding(self) -> Finding:
        counts = Counter(o.verdict for o in self.report.observations)
        usable = sum(counts[v] for v in (Verdict.CLEAN, Verdict.TAMPERED, Verdict.SUSPICIOUS))
        total = len(self.report.observations)
        evidence = [f"{v.value} = {n}" for v, n in sorted(counts.items(), key=lambda kv: kv[0].value)]
        evidence.append(f"usable evidence in {usable} of {total} trials")

        refused = counts[Verdict.REFUSED]
        if refused:
            evidence.append(
                f"{refused} trial(s) were refused by the model in prose rather than "
                f"answered with a tool call"
            )

        if counts[Verdict.TAMPERED]:
            summary = ("Tampering was observed, so the checks below are confirmed positives. "
                       "A clean result on the remaining probes still proves nothing.")
            severity = Severity.INFO
        elif usable == 0:
            summary = ("No trial produced usable evidence. Every request errored, was refused, "
                       "or returned no tool call, so this run says nothing about the endpoint.")
            severity = Severity.MEDIUM
        elif total and usable / total < 0.5:
            # Reporting "no tampering observed" off a handful of usable trials
            # would read as an all-clear it has not earned.
            summary = (
                f"This run is inconclusive: only {usable} of {total} trials produced a "
                f"comparable tool call. "
                + (f"{refused} were refused outright - a probe payload that looks like the "
                   "attack it detects gets declined by a safety-trained model, which costs "
                   "coverage and says nothing about the endpoint. " if refused else "")
                + "Re-run against a model that follows tool_choice, or with probes the model "
                "will comply with, before drawing any conclusion."
            )
            severity = Severity.MEDIUM
        else:
            summary = (
                "No tampering was observed in this run. That is not a clean bill of health. "
                "A conditional-delivery router (AC-1.b) behaves honestly until its trigger "
                "fires: observed triggers include a 50-request warm-up, autonomous "
                "auto-approve sessions, and specific project languages. Because the trigger "
                "predicate lives on the server, no finite probe can establish that an "
                "endpoint is clean."
            )
            severity = Severity.INFO

        return Finding(
            id="coverage.summary", attack_class=AttackClass.AC1B,
            severity=severity, title="Coverage and what this run can conclude",
            summary=summary, evidence=evidence,
            remediation=("Vary the session fingerprint and add warm-up traffic with "
                         "`agent-police campaign` to widen trigger coverage."),
            confidence="high",
        )

    def _canary_findings(self) -> list[Finding]:
        observable = [c for c in self._issued_canaries if c.observable]
        decoys = [c for c in self._issued_canaries if not c.observable]
        tokens = [c.token for c in observable]
        hits = self.canaries.hits(tokens) if tokens else []

        findings: list[Finding] = []
        if hits:
            evidence = []
            for h in hits[:10]:
                if h.kind == "dns":
                    # A DNS hit is seen from the recursive resolver, never from
                    # whoever asked it. Saying "fetched from" would overstate it.
                    evidence.append(
                        f"dns canary {h.token[:10]}... resolved; query arrived via resolver "
                        f"{h.source_ip or 'unknown'} (the resolver, not the party that "
                        f"looked it up)"
                    )
                else:
                    evidence.append(
                        f"{h.kind} canary {h.token[:10]}... fetched by {h.source_ip or 'unknown'} "
                        f"(user-agent: {h.user_agent or 'none'})"
                    )
            findings.append(Finding(
                id="ac2.canary_hit", attack_class=AttackClass.AC2,
                severity=Severity.CRITICAL,
                title="A planted credential was used",
                summary=(
                    "A canary that existed only inside traffic sent to this endpoint was "
                    "subsequently accessed from elsewhere. Nothing legitimate reads a value "
                    "out of a prompt and then contacts it. Something on the path retained "
                    "and acted on your plaintext."
                ),
                evidence=evidence,
                remediation=("Rotate every real credential that has passed through this "
                             "endpoint, and stop using it."),
                confidence="high",
            ))
        elif observable:
            findings.append(Finding(
                id="ac2.canary_pending", attack_class=AttackClass.AC2,
                severity=Severity.INFO,
                title="Canaries planted, no use observed yet",
                summary=(
                    "AC-2 leaves traffic unchanged, so it cannot be detected at request time. "
                    "Harvested credentials are typically validated and resold before use, so "
                    "absence of a hit minutes after planting means very little. Check again "
                    "over the coming days."
                ),
                evidence=[
                    f"{len(observable)} observable canaries planted across "
                    f"{len({c.placement for c in observable})} placements",
                    f"{len(decoys)} credential-shaped decoys planted (require your own "
                    f"canary infrastructure to observe)",
                    "http canaries identify the caller directly; dns canaries catch anything "
                    "that merely resolves a harvested hostname, but only ever reveal the "
                    "resolver it asked",
                ],
                remediation="Re-check with `agent-police canary check`.",
                confidence="high",
            ))
        return findings

    def _conditional_findings(self, by_probe) -> list[Finding]:
        """Report which session fingerprints, if any, changed the outcome."""
        cells: dict[str, Counter] = defaultdict(Counter)
        for observation in self.report.observations:
            cells[observation.cell][observation.verdict] += 1
        if len(cells) < 2:
            return []

        dirty = {c: n for c, n in cells.items() if n[Verdict.TAMPERED]}
        clean = {c: n for c, n in cells.items() if not n[Verdict.TAMPERED]}
        if not dirty:
            return []

        evidence = [f"TAMPERED in: {c} ({n[Verdict.TAMPERED]} trials)" for c, n in dirty.items()]
        evidence += [f"clean in:    {c}" for c in list(clean)[:6]]
        return [Finding(
            id="ac1b.selective", attack_class=AttackClass.AC1B,
            severity=Severity.CRITICAL,
            title="Tampering is gated on session features",
            summary=(
                "The endpoint rewrote tool calls for some session fingerprints and not others. "
                "That is conditional delivery: routine probes see honest behaviour while "
                "sessions matching the trigger receive the payload. Any audit that happened "
                "to test only the clean cells would have passed this endpoint."
            ),
            evidence=evidence,
            remediation="Treat the endpoint as compromised for all traffic, not just the matching cells.",
            confidence="high",
        )]
