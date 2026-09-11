"""Background audit jobs, with a deliberately short credential lifetime.

The service asks visitors for a key to an endpoint they do not trust. That is
exactly the trust problem the paper describes, so the handling rules are strict:

  * the key lives only in the worker thread's local AuditConfig;
  * it is never written to the job record, the database, a log line or a report;
  * the reference is dropped as soon as the run finishes;
  * jobs expire and are deleted.

Nothing here makes the service trustworthy on its own. It makes the blast
radius small and the claims checkable.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from ..canary import CanaryProvider
from ..models import AttackClass, AuditReport, SessionFingerprint
from ..runner import AuditConfig, Auditor

JOB_TTL_SECONDS = 30 * 60
MAX_ACTIVE_JOBS = 6

DEFAULT_RATE_PER_MINUTE = 60.0
"""Requests per minute the hosted service sends to the endpoint under test.

One per second: fast enough that a standard audit finishes in about a minute,
slow enough that an audit never looks like abuse to the operator.
"""

REQUIRE_PUBLIC_PEER = True
"""Re-check the connected address on every response.

On by default because the hosted service accepts targets from strangers and
DNS can be rebound between validation and connection. Tests point at a
loopback fixture and turn it off.
"""

# Preset -> (attack classes, repeats, fingerprints, plant canaries)
MODES: dict[str, dict[str, Any]] = {
    "quick": {
        "classes": [AttackClass.AC1],
        "repeats": 1,
        "fingerprints": [SessionFingerprint()],
        "canaries": False,
        "label": "Quick - AC-1 only, ~7 requests",
    },
    "standard": {
        "classes": [AttackClass.AC1, AttackClass.AC1A],
        "repeats": 2,
        "fingerprints": [SessionFingerprint()],
        "canaries": False,
        "label": "Standard - AC-1 and AC-1.a, ~28 requests",
    },
    "deep": {
        "classes": [AttackClass.AC1, AttackClass.AC1A, AttackClass.AC2],
        "repeats": 2,
        "fingerprints": [
            SessionFingerprint(tool_name="Bash", project_lang="python", autonomy="interactive"),
            SessionFingerprint(tool_name="run_command", project_lang="rust", autonomy="yolo"),
        ],
        "canaries": True,
        "label": "Deep - all classes across two session fingerprints, ~72 requests",
    },
}


@dataclass
class Job:
    id: str
    target: str
    mode: str
    status: str = "queued"  # queued | running | done | failed
    created_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    done: int = 0
    total: int = 0
    label: str = ""
    report: AuditReport | None = None
    error: str | None = None
    audit_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "mode": self.mode,
            "status": self.status,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "progress": {"done": self.done, "total": self.total, "label": self.label},
            "error": self.error,
            "audit_id": self.audit_id,
            "report": self.report.to_dict() if self.report else None,
        }


class JobManager:
    def __init__(self, canary_provider_factory):
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._canary_provider_factory = canary_provider_factory

    def active_count(self) -> int:
        with self._lock:
            return sum(1 for j in self._jobs.values() if j.status in ("queued", "running"))

    def submit(self, *, base_url: str, api_key: str, model: str, wire: str,
               mode: str, rate: float | None = None) -> Job:
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode!r}")
        if self.active_count() >= MAX_ACTIVE_JOBS:
            raise RuntimeError("too many audits in flight; try again shortly")

        self.reap()
        job = Job(id=uuid.uuid4().hex[:16], target=base_url, mode=mode)
        job.audit_id = job.id
        with self._lock:
            self._jobs[job.id] = job

        preset = MODES[mode]
        rate = DEFAULT_RATE_PER_MINUTE if rate is None else rate
        # The key is passed by argument into the thread and never stored on the
        # job record, so nothing that outlives the run holds a reference to it.
        thread = threading.Thread(
            target=self._run, args=(job, base_url, api_key, model, wire, preset, rate),
            daemon=True, name=f"audit-{job.id}",
        )
        thread.start()
        return job

    def _run(self, job: Job, base_url: str, api_key: str, model: str,
             wire: str, preset: dict[str, Any], rate: float) -> None:
        job.status = "running"
        provider: CanaryProvider = self._canary_provider_factory(
            job.audit_id if preset["canaries"] else None
        )
        try:
            config = AuditConfig(
                base_url=base_url, api_key=api_key, model=model, wire_name=wire,
                repeats=preset["repeats"], rate_per_minute=rate,
                classes=list(preset["classes"]),
                fingerprints=list(preset["fingerprints"]),
                skip_hygiene=False,
                require_public_peer=REQUIRE_PUBLIC_PEER,
            )
            auditor = Auditor(config, provider)

            def progress(label: str, done: int, total: int) -> None:
                job.done, job.total, job.label = done, total, label

            job.report = auditor.run(progress)
            job.status = "done"
        except Exception as exc:  # surfaced to the user, never logged with the key
            job.status = "failed"
            job.error = f"{type(exc).__name__}: {exc}".replace(api_key, "[REDACTED]")
        finally:
            api_key = ""  # drop this frame's reference
            del api_key
            job.finished_at = time.time()

    def get(self, job_id: str) -> Job | None:
        self.reap()
        with self._lock:
            return self._jobs.get(job_id)

    def reap(self) -> None:
        cutoff = time.time() - JOB_TTL_SECONDS
        with self._lock:
            stale = [jid for jid, j in self._jobs.items()
                     if (j.finished_at or j.created_at) < cutoff]
            for jid in stale:
                del self._jobs[jid]
