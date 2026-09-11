"""The hosted service: a web UI, an audit API and a canary collector."""

from __future__ import annotations

import os
import re
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import __version__
from ..canary import CanaryHit, LocalCanaryProvider, NullCanaryProvider
from ..client import RouterClient
from ..detect.inspect import inspect_command
from ..probes.hygiene import run_hygiene
from ..store import SqliteCanaryStore
from ..wire import get_wire
from .guard import TargetRejected, assert_public_target
from .jobs import MODES, JobManager

STATIC_DIR = Path(__file__).parent / "static"

# Per-IP budgets. Audits cost the visitor real tokens and cost us outbound
# requests, so they are scarcer than the free checks.
LIMITS = {"audit": (5, 3600), "preflight": (30, 3600), "inspect": (120, 3600),
          "register": (40, 3600)}

TOKEN_RE = re.compile(r"^[a-z2-7]{8,64}$")
"""Tokens the collector will accept for registration: the alphabet new_token uses."""


class RateLimit:
    def __init__(self) -> None:
        self._hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def check(self, bucket: str, client_ip: str) -> None:
        limit, window = LIMITS[bucket]
        now = time.time()
        queue = self._hits[(bucket, client_ip)]
        while queue and queue[0] < now - window:
            queue.popleft()
        if len(queue) >= limit:
            retry = int(queue[0] + window - now)
            raise HTTPException(429, f"Rate limit reached for {bucket}. Try again in {retry}s.")
        queue.append(now)


class AuditRequest(BaseModel):
    base_url: str = Field(min_length=4, max_length=300)
    api_key: str = Field(min_length=8, max_length=500)
    model: str = Field(min_length=1, max_length=120)
    wire: str = Field(default="anthropic", pattern="^(anthropic|openai)$")
    mode: str = Field(default="standard", pattern="^(quick|standard|deep)$")


class PreflightRequest(BaseModel):
    base_url: str = Field(min_length=4, max_length=300)
    wire: str = Field(default="anthropic", pattern="^(anthropic|openai)$")


class InspectRequest(BaseModel):
    command: str = Field(min_length=1, max_length=8000)


class CanaryRegistration(BaseModel):
    """Tokens a CLI run planted, so the collector recognises their callbacks.

    Registration carries no secret and grants nothing: it only teaches the
    collector which random strings to record a hit for. Everything else about
    the audit - the endpoint, the key, the findings - stays on the machine
    that ran it.
    """

    audit_id: str = Field(min_length=4, max_length=64, pattern=r"^[A-Za-z0-9_.\-]+$")
    # Deliberately not dict[str, str]: the client sends Canary.to_dict(), which
    # carries a bool and a float alongside the strings. Constraining the value
    # type here rejected every real payload with a 422 while unit tests that
    # hand-built string-only dicts passed. The fields this endpoint actually
    # uses are validated individually below.
    canaries: list[dict[str, Any]] = Field(min_length=1, max_length=200)


def client_ip(request: Request, forwarded: str | None) -> str:
    """Best-available caller address.

    A canary hit is evidence, so the address has to be one the caller cannot
    choose. CDNs that overwrite a dedicated header are trusted first:
    X-Forwarded-For is *appended* to by most proxies, so an attacker-supplied
    value survives as the leftmost entry and must not be preferred.
    """
    for header in ("cf-connecting-ip", "true-client-ip", "x-real-ip"):
        value = request.headers.get(header)
        if value and value.strip():
            return value.strip()
    if forwarded:
        # Fall back to the last hop we were told about rather than the first:
        # the tail is written by infrastructure, the head by whoever called.
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if parts:
            return parts[-1]
    return request.client.host if request.client else "unknown"


def create_app(*, canary_db: str, canary_base: str, canary_dns: str | None) -> FastAPI:
    store = SqliteCanaryStore(canary_db)
    limiter = RateLimit()

    class AuditScopedProvider(LocalCanaryProvider):
        """Tags every canary it issues with the audit that planted it."""

        def __init__(self, audit_id: str):
            super().__init__(canary_base, canary_dns, store)
            self.audit_id = audit_id

        def issue(self, kind: str, placement: str):
            canary = super().issue(kind, placement)
            store.register(canary, self.audit_id)
            return canary

    def provider_factory(audit_id: str | None):
        return AuditScopedProvider(audit_id) if audit_id else NullCanaryProvider()

    jobs = JobManager(provider_factory)
    app = FastAPI(title="agent-police", version=__version__, docs_url="/api/docs")

    # -- pages ---------------------------------------------------------
    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    def _source_sha() -> str | None:
        checksum = STATIC_DIR / "download" / "SHA256"
        try:
            return checksum.read_text("utf-8").strip() or None
        except OSError:
            return None

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {
            "ok": True,
            "version": __version__,
            "source_sha256": _source_sha(),
            "canary_http": canary_base,
            "canary_dns": canary_dns,
            "modes": {k: v["label"] for k, v in MODES.items()},
        }

    # -- canary collector ----------------------------------------------
    @app.get("/c/{token}", include_in_schema=False)
    @app.get("/c/{token}/{rest:path}", include_in_schema=False)
    def canary_hit(token: str, request: Request, rest: str = "",
                   x_forwarded_for: str | None = Header(default=None)) -> PlainTextResponse:
        """Anything that fetches a planted URL lands here.

        The response is deliberately inert: no script, no redirect, nothing an
        agent could act on. It exists only to record that the fetch happened.
        """
        canary = store.lookup(token)
        if canary is not None:
            store.record_hit(CanaryHit(
                token=token, kind="url", at=time.time(),
                source_ip=client_ip(request, x_forwarded_for),
                user_agent=request.headers.get("user-agent"),
                detail=f"GET /c/{token}/{rest}".rstrip("/"),
            ))
        return PlainTextResponse(
            "agent-police canary\n"
            "This URL existed only inside probe traffic sent to one API endpoint.\n"
            "Fetching it has been recorded.\n",
            status_code=200,
        )

    @app.post("/api/canary/register")
    def canary_register(body: CanaryRegistration, request: Request,
                        x_forwarded_for: str | None = Header(default=None)) -> dict[str, Any]:
        limiter.check("register", client_ip(request, x_forwarded_for))
        from ..canary import OBSERVABLE_KINDS, Canary

        stored = 0
        for item in body.canaries:
            token = (item.get("token") or "").strip()
            kind = (item.get("kind") or "").strip()
            if kind not in OBSERVABLE_KINDS or not TOKEN_RE.match(token):
                continue
            store.register(Canary(
                token=token, kind=kind, value=str(item.get("value", ""))[:300],
                placement=str(item.get("placement", "unknown"))[:60],
                observable=True, note="registered by a CLI run",
            ), body.audit_id)
            stored += 1
        return {"audit_id": body.audit_id, "registered": stored,
                "rejected": len(body.canaries) - stored}

    @app.get("/api/canary/{audit_id}")
    def canary_status(audit_id: str) -> dict[str, Any]:
        hits = store.hits_for_audit(audit_id)
        tokens = store.tokens_for_audit(audit_id)
        return {
            "audit_id": audit_id,
            "planted": len(tokens),
            "hits": [h.to_dict() for h in hits],
        }

    # -- free checks ----------------------------------------------------
    @app.post("/api/inspect")
    def inspect(body: InspectRequest, request: Request,
                x_forwarded_for: str | None = Header(default=None)) -> dict[str, Any]:
        limiter.check("inspect", client_ip(request, x_forwarded_for))
        return {"findings": inspect_command(body.command)}

    @app.post("/api/preflight")
    def preflight(body: PreflightRequest, request: Request,
                  x_forwarded_for: str | None = Header(default=None)) -> dict[str, Any]:
        limiter.check("preflight", client_ip(request, x_forwarded_for))
        try:
            host = assert_public_target(body.base_url)
        except TargetRejected as exc:
            raise HTTPException(400, str(exc)) from None

        wire = get_wire(body.wire)
        with RouterClient(body.base_url, "", wire, timeout=20.0,
                          rate_per_minute=120.0, require_public_peer=True) as client:
            findings = run_hygiene(client)
        return {
            "host": host,
            "findings": [f.to_dict() for f in
                         sorted(findings, key=lambda f: f.severity.rank)],
        }

    # -- audits ---------------------------------------------------------
    @app.post("/api/audit")
    def start_audit(body: AuditRequest, request: Request,
                    x_forwarded_for: str | None = Header(default=None)) -> dict[str, Any]:
        limiter.check("audit", client_ip(request, x_forwarded_for))
        try:
            assert_public_target(body.base_url)
        except TargetRejected as exc:
            raise HTTPException(400, str(exc)) from None
        try:
            job = jobs.submit(
                base_url=body.base_url, api_key=body.api_key, model=body.model,
                wire=body.wire, mode=body.mode,
            )
        except RuntimeError as exc:
            raise HTTPException(503, str(exc)) from None
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        return job.to_dict()

    @app.get("/api/audit/{job_id}")
    def audit_status(job_id: str) -> dict[str, Any]:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(404, "Unknown or expired audit. Results are kept for 30 minutes.")
        return job.to_dict()

    @app.exception_handler(TargetRejected)
    def _rejected(request: Request, exc: TargetRejected) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=400)

    return app


def start_dns_if_configured(canary_db: str, canary_dns: str | None):
    """Bring up the DNS canary collector when a delegated zone is configured."""
    if not canary_dns:
        return None
    from .dnscanary import start_dns_collector
    port = int(os.environ.get("AGENT_POLICE_DNS_PORT", "53"))
    try:
        return start_dns_collector(
            zone=canary_dns,
            store=SqliteCanaryStore(canary_db),
            host=os.environ.get("AGENT_POLICE_DNS_HOST", "0.0.0.0"),
            port=port,
            answer_a=os.environ.get("AGENT_POLICE_DNS_A"),
            answer_aaaa=os.environ.get("AGENT_POLICE_DNS_AAAA"),
            nameserver=os.environ.get("AGENT_POLICE_DNS_NS"),
        )
    except OSError as exc:
        # Not fatal: HTTP canaries keep working, DNS ones simply never fire.
        print(f"[agent-police] DNS canary collector not started on :{port} ({exc}). "
              f"HTTP canaries are unaffected.")
        return None


def serve(*, host: str = "127.0.0.1", port: int = 8080, canary_db: str,
          canary_base: str, canary_dns: str | None = None) -> None:
    import uvicorn
    start_dns_if_configured(canary_db, canary_dns)
    app = create_app(canary_db=canary_db, canary_base=canary_base, canary_dns=canary_dns)
    uvicorn.run(app, host=host, port=port, log_level="info",
                forwarded_allow_ips=os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1"))


app = None
if os.environ.get("AGENT_POLICE_AUTOAPP"):  # for `uvicorn agentpolice.server.app:app`
    _db = os.environ.get("AGENT_POLICE_DB", "/data/canaries.db")
    _dns = os.environ.get("AGENT_POLICE_CANARY_DNS") or None
    start_dns_if_configured(_db, _dns)
    app = create_app(
        canary_db=_db,
        canary_base=os.environ.get("AGENT_POLICE_CANARY_BASE", "https://security.romaapi.com"),
        canary_dns=_dns,
    )
