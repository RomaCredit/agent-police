"""Core data model shared by every probe, detector and renderer."""

from __future__ import annotations

import enum
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any


class AttackClass(str, enum.Enum):
    """Attack taxonomy from arXiv:2604.08407 section 4, plus a hygiene bucket."""

    AC1 = "AC-1"
    AC1A = "AC-1.a"
    AC1B = "AC-1.b"
    AC2 = "AC-2"
    HYGIENE = "HYGIENE"

    @property
    def title(self) -> str:
        return {
            "AC-1": "Response-side payload injection",
            "AC-1.a": "Dependency-targeted injection",
            "AC-1.b": "Conditional delivery",
            "AC-2": "Passive secret exfiltration",
            "HYGIENE": "Supply-chain hygiene",
        }[self.value]


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }[self.value]


class Verdict(str, enum.Enum):
    """Outcome of a single probe trial."""

    CLEAN = "clean"
    """Observed tool call matched the expectation exactly."""

    TAMPERED = "tampered"
    """Observed tool call deviated in an adversarial way."""

    SUSPICIOUS = "suspicious"
    """Deviation that is adversarial in shape but could be model noise."""

    INCONCLUSIVE = "inconclusive"
    """Cosmetic deviation, or the model declined to follow the instruction."""

    NO_TOOL_CALL = "no_tool_call"
    """The endpoint returned no tool call at all."""

    REFUSED = "refused"
    """The model declined the probe in prose instead of emitting a tool call.

    Distinct from NO_TOOL_CALL because it is actionable: a probe payload that
    looks like the attack it detects gets refused by a safety-trained model,
    which costs coverage rather than indicating anything about the endpoint.
    """

    ERROR = "error"
    """Transport or API error; the trial produced no usable evidence."""

    @property
    def is_evidence(self) -> bool:
        """True when the trial produced a usable clean/dirty signal."""
        return self in (Verdict.CLEAN, Verdict.TAMPERED, Verdict.SUSPICIOUS)


@dataclass(slots=True)
class SessionFingerprint:
    """The session-level features an AC-1.b trigger predicate can key on.

    Section 4.2.2 lists five trigger families; these fields are the ones a
    client can actually vary from the outside.
    """

    tool_name: str = "Bash"
    project_lang: str | None = None
    autonomy: str = "interactive"  # "interactive" | "yolo"
    warmup_index: int = 0
    hour_of_day: int | None = None

    def cell(self) -> str:
        """Stable identifier for the grid cell this fingerprint belongs to."""
        return "|".join(
            [
                f"tool={self.tool_name}",
                f"lang={self.project_lang or '-'}",
                f"autonomy={self.autonomy}",
                f"warmup={self.warmup_index}",
            ]
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Expectation:
    """What a correctly-behaving endpoint must return for a trial."""

    tool_name: str
    args: dict[str, str]
    """Argument name -> exact expected string value."""


@dataclass(slots=True)
class ToolCall:
    name: str
    arguments: dict[str, Any]
    raw: Any = None

    def arg_str(self, key: str) -> str | None:
        value = self.arguments.get(key)
        if value is None:
            return None
        return value if isinstance(value, str) else json.dumps(value, sort_keys=True)


@dataclass(slots=True)
class Deviation:
    """A single semantic difference between expected and observed arguments."""

    kind: str
    detail: str
    expected: str | None = None
    observed: str | None = None
    adversarial: bool = False
    """True when the shape of the change is one an attacker would make."""

    attack_class: AttackClass | None = None

    signature: str | None = None
    """The attacker-controlled invariant in this change (a host, a package name).

    Probe payloads carry a per-trial nonce, so the full argument differs every
    time even under a fixed rewrite rule. Aggregation compares signatures, not
    whole strings, to tell a deliberate substitution from model noise.
    """

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if self.attack_class is not None:
            d["attack_class"] = self.attack_class.value
        return d


@dataclass(slots=True)
class Trial:
    """One request/response pair with a known-correct answer."""

    probe_id: str
    attack_class: AttackClass
    nonce: str
    request: dict[str, Any]
    expectation: Expectation
    fingerprint: SessionFingerprint = field(default_factory=SessionFingerprint)
    trial_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Observation:
    """The evaluated result of one trial."""

    trial_id: str
    probe_id: str
    attack_class: AttackClass
    verdict: Verdict
    nonce: str
    cell: str
    deviations: list[Deviation] = field(default_factory=list)
    observed_tool: str | None = None
    observed_args: dict[str, Any] = field(default_factory=dict)
    response_text: str = ""
    latency_ms: float | None = None
    error: str | None = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trial_id": self.trial_id,
            "probe_id": self.probe_id,
            "attack_class": self.attack_class.value,
            "verdict": self.verdict.value,
            "nonce": self.nonce,
            "cell": self.cell,
            "deviations": [d.to_dict() for d in self.deviations],
            "observed_tool": self.observed_tool,
            "observed_args": self.observed_args,
            "response_text": self.response_text[:400],
            "latency_ms": self.latency_ms,
            "error": self.error,
            "timestamp": self.timestamp,
        }


@dataclass(slots=True)
class Finding:
    """A reportable conclusion, aggregated over one or more observations."""

    id: str
    attack_class: AttackClass
    severity: Severity
    title: str
    summary: str
    evidence: list[str] = field(default_factory=list)
    remediation: str | None = None
    confidence: str = "medium"  # "high" | "medium" | "low"
    observations: list[str] = field(default_factory=list)  # trial ids

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "attack_class": self.attack_class.value,
            "severity": self.severity.value,
            "title": self.title,
            "summary": self.summary,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "observations": self.observations,
        }


@dataclass
class AuditReport:
    target: str
    wire_format: str
    model: str
    started_at: float
    finished_at: float | None = None
    findings: list[Finding] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    canaries: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def worst(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return min((f.severity for f in self.findings), key=lambda s: s.rank)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (f.severity.rank, f.attack_class.value))

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "agent-police",
            "target": self.target,
            "wire_format": self.wire_format,
            "model": self.model,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "worst_severity": self.worst.value,
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "observations": [o.to_dict() for o in self.observations],
            "canaries": self.canaries,
            "notes": self.notes,
        }
