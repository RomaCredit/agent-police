"""Endpoint hygiene: everything observable without a tool-call probe.

None of these checks prove tampering. They establish what you are actually
talking to, which is the question the paper says users cannot currently answer:
the client configures only the first hop, and subsequent hops are invisible.
"""

from __future__ import annotations

import statistics
from typing import Any

from ..canary import new_token
from ..client import RouterClient
from ..detect import fingerprint
from ..models import AttackClass, Finding, Severity

HY = AttackClass.HYGIENE
BOGUS_KEY = "sk-agentpolice-invalid-0000000000000000000000"


def _f(fid: str, severity: Severity, title: str, summary: str,
       evidence: list[str], remediation: str | None = None,
       confidence: str = "high") -> Finding:
    return Finding(id=fid, attack_class=HY, severity=severity, title=title,
                   summary=summary, evidence=evidence, remediation=remediation,
                   confidence=confidence)


def check_identity(client: RouterClient) -> list[Finding]:
    category, detail = fingerprint.classify_host(client.base_url)
    if category == "first_party":
        return [_f("hygiene.identity", Severity.INFO, "First-party provider endpoint",
                   detail + ". No intermediary is configured on the first hop.",
                   [f"base_url = {client.base_url}"])]
    severity = Severity.LOW if category == "known_aggregator" else Severity.MEDIUM
    return [_f(
        "hygiene.identity", severity, "Traffic is routed through an intermediary",
        detail + ". This endpoint terminates your TLS session and re-originates a separate "
        "connection upstream, so it reads and can rewrite every prompt, tool definition, "
        "API key and returned tool call in plaintext. No end-to-end integrity mechanism "
        "binds what the model produced to what your agent executes.",
        [f"base_url = {client.base_url}", f"classification = {category}"],
        "Prefer a first-party endpoint for agentic workloads. If you must use an "
        "intermediary, treat every tool call it returns as untrusted input.",
    )]


def check_tls(client: RouterClient) -> list[Finding]:
    tls = client.tls
    if tls is None:
        return []
    if tls.error:
        return [_f("hygiene.tls", Severity.INFO, "TLS details unavailable",
                   f"Could not inspect the TLS session: {tls.error}", [], confidence="low")]
    host = fingerprint.host_of(client.base_url)
    evidence = [
        f"protocol = {tls.negotiated_protocol}",
        f"cipher = {tls.cipher}",
        f"issuer = {tls.issuer}",
        f"subject = {tls.subject}",
        f"expires = {tls.not_after}",
    ]
    if tls.sans:
        evidence.append("SANs = " + ", ".join(tls.sans[:12]))
    matched = any(
        host == san or (san.startswith("*.") and host.endswith(san[1:]))
        for san in tls.sans
    )
    if tls.sans and not matched:
        return [_f("hygiene.tls", Severity.MEDIUM, "Certificate does not cover the requested host",
                   f"The presented certificate does not list {host} in its SANs.", evidence,
                   "Verify you are connecting to the host you think you are.")]
    return [_f("hygiene.tls", Severity.INFO, "TLS session details",
               "Transport security authenticates the endpoint you chose. It says nothing "
               "about whether the tool calls it returns preserve upstream semantics.",
               evidence)]


def measure_catch_all(client: RouterClient) -> fingerprint.ControlResponse:
    """Ask for a path that cannot exist, to learn what "not found" looks like.

    Routers that serve a single-page app answer 200 with the same HTML shell
    for every unknown path. Without this measurement, "GET /health/liveliness
    returned 200" reads as evidence of LiteLLM when it is really just the
    catch-all - a false positive confirmed against a live new-api deployment.
    """
    probe_path = f"/agent-police-control-{new_token(12)}"
    result = client.get(probe_path)
    return fingerprint.ControlResponse(
        status=result.status,
        content_type=result.headers.get("content-type", ""),
        body_len=len(result.text or ""),
        body_head=(result.text or "")[:120],
    )


def check_signatures(client: RouterClient,
                     control: fingerprint.ControlResponse | None = None) -> list[Finding]:
    findings: list[Finding] = []
    control = control if control is not None else measure_catch_all(client)

    if control.is_catch_all:
        findings.append(_f(
            "hygiene.catch_all", Severity.INFO,
            "Endpoint answers any path with a success response",
            "A randomly generated path that cannot exist returned "
            f"HTTP {control.status}. Checks based on whether a path merely responds "
            "carry no information here, so agent-police discarded them and matched "
            "software only on response content.",
            [f"control probe returned {control.status} {control.content_type} "
             f"({control.body_len} bytes)"],
            confidence="high",
        ))

    for sig in fingerprint.signatures():
        evidence: list[str] = []
        strong_hit = False
        for check in sig.get("checks", []):
            result = client.get(check.get("path", "/"))
            hit = fingerprint.check_matches(
                check, result.status, result.body, result.text,
                content_type=result.headers.get("content-type", ""),
                control=control,
            )
            if hit:
                evidence.append(hit)
                strong_hit = strong_hit or fingerprint.is_strong(check)

        # Reachability alone is not identification.
        if evidence and strong_hit:
            findings.append(_f(
                f"hygiene.software.{sig['id']}", Severity.INFO,
                f"Endpoint software looks like {sig['name']}",
                sig.get("note", ""), evidence,
                "Running this software is normal. Confirm you intended to route through it.",
                confidence=sig.get("confidence", "low"),
            ))
    return findings


def check_provider_headers(client: RouterClient, sample: dict[str, str]) -> list[Finding]:
    expected = client.wire.provider_headers
    present = [h for h in expected if h in sample]
    missing = [h for h in expected if h not in sample]
    if not missing:
        return [_f("hygiene.headers", Severity.INFO, "Provider response headers present",
                   "The response carries the metadata headers a first-party provider sets.",
                   [f"present = {', '.join(present)}"])]
    severity = Severity.LOW if present else Severity.MEDIUM
    return [_f(
        "hygiene.headers", severity, "Provider response headers are missing",
        "The endpoint strips or does not reproduce the metadata headers the upstream "
        "provider normally returns, which means the response body you receive was "
        "assembled by the intermediary rather than passed through untouched.",
        [f"missing = {', '.join(missing)}"] + ([f"present = {', '.join(present)}"] if present else [])
        + [f"server = {sample.get('server', '(none)')}"],
        "Treat the response as re-originated. Request-id correlation with the upstream "
        "provider is not available through this path.",
        confidence="medium",
    )]


def check_models(client: RouterClient) -> list[Finding]:
    result = client.models()
    if not result.ok or not result.body:
        return [_f("hygiene.models", Severity.INFO, "Model list unavailable",
                   f"GET {client.wire.models_path} returned {result.status}.", [],
                   confidence="low")]
    data = result.body.get("data")
    ids: list[str] = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                ids.append(item["id"])
    if not ids:
        return []
    vendors = set()
    for mid in ids:
        low = mid.lower()
        for vendor, keys in {
            "anthropic": ("claude",), "openai": ("gpt", "o1", "o3", "o4", "codex"),
            "google": ("gemini", "gemma"), "meta": ("llama",),
            "deepseek": ("deepseek",), "alibaba": ("qwen", "tongyi"),
            "moonshot": ("kimi",), "zhipu": ("glm",), "mistral": ("mistral", "mixtral"),
            "xai": ("grok",), "xiaomi": ("mimo",),
        }.items():
            if any(k in low for k in keys):
                vendors.add(vendor)
    if len(vendors) >= 2:
        return [_f(
            "hygiene.models", Severity.LOW, "Endpoint aggregates multiple model vendors",
            f"The model list spans {len(vendors)} vendors ({', '.join(sorted(vendors))}) and "
            f"{len(ids)} model ids. A single endpoint fronting several upstreams is a router, "
            "and routers compose: the hop you configured may itself forward to further hops "
            "you cannot see.",
            [f"models = {len(ids)}", "sample = " + ", ".join(sorted(ids)[:10])],
            "Ask the operator which upstream path each model takes, and who else is on it.",
        )]
    return [_f("hygiene.models", Severity.INFO, "Model list",
               f"{len(ids)} model ids advertised.", ["sample = " + ", ".join(sorted(ids)[:10])])]


def check_auth_enforcement(client: RouterClient) -> list[Finding]:
    """A bogus key that still works means the endpoint is an open relay."""
    body = client.wire.build_request(
        model="gpt-4o-mini" if client.wire.name == "openai" else "claude-3-5-haiku-latest",
        system="reply with the single word ok",
        user="reply with the single word ok",
        tools=[],
        max_tokens=16,
    )
    body.pop("tools", None)
    result = client.chat_with_key(body, BOGUS_KEY)
    if result.status in (401, 403):
        return [_f("hygiene.auth", Severity.INFO, "Authentication is enforced",
                   f"A syntactically invalid key was rejected with HTTP {result.status}.", [])]
    if result.ok:
        return [_f(
            "hygiene.auth", Severity.HIGH, "Endpoint answers requests with an invalid key",
            "A key that cannot correspond to any account was served a successful response. "
            "The endpoint is an open relay: anyone who finds it can spend the operator's "
            "upstream credential, and any traffic you send shares a channel with unknown "
            "third parties. This is the configuration the paper's decoy study found being "
            "absorbed into commodity relay chains within days.",
            [f"invalid key returned HTTP {result.status}",
             f"latency = {result.latency_ms:.0f} ms"],
            "Do not send production prompts or credentials through this endpoint. "
            "If you operate it, require authentication immediately.",
        )]
    return [_f("hygiene.auth", Severity.INFO, "Invalid key rejected",
               f"An invalid key produced HTTP {result.status}.", [],
               confidence="medium")]


def check_error_shape(client: RouterClient) -> list[Finding]:
    result = client.malformed_chat()
    if result.body is None:
        return [_f("hygiene.errors", Severity.LOW, "Non-JSON error response",
                   "A malformed request produced a response that is not JSON, so the endpoint "
                   "is not reproducing the provider's error envelope.",
                   [f"status = {result.status}", "body = " + result.text[:200]],
                   confidence="medium")]
    has_error_obj = isinstance(result.body.get("error"), dict)
    if not has_error_obj:
        return [_f(
            "hygiene.errors", Severity.LOW, "Error envelope differs from the provider's",
            "A malformed request produced an error body that does not match the upstream "
            "provider's documented shape, which means the endpoint generates its own errors "
            "rather than relaying them. It is parsing and reconstructing bodies in both "
            "directions.",
            [f"status = {result.status}", "keys = " + ", ".join(sorted(result.body)[:8])],
            confidence="medium",
        )]
    return [_f("hygiene.errors", Severity.INFO, "Error envelope matches provider shape",
               "Malformed requests produce a provider-shaped error object.",
               [f"status = {result.status}"])]


def check_redirects(client: RouterClient) -> list[Finding]:
    result = client.get("/v1/models", authed=True)
    if result.status in (301, 302, 307, 308) and result.redirect_to:
        target_host = fingerprint.host_of(result.redirect_to)
        own_host = fingerprint.host_of(client.base_url)
        if target_host and target_host != own_host:
            return [_f(
                "hygiene.redirect", Severity.MEDIUM, "Endpoint redirects to a different host",
                f"Requests are redirected from {own_host} to {target_host}, adding a hop you "
                "did not configure.",
                [f"{result.status} -> {result.redirect_to}"],
                "Point your client directly at the final host so you know who terminates TLS.",
            )]
    return []


def latency_finding(samples: list[float]) -> list[Finding]:
    if len(samples) < 3:
        return []
    median = statistics.median(samples)
    spread = max(samples) - min(samples)
    return [_f("hygiene.latency", Severity.INFO, "Round-trip latency",
               "Buffered rewriting costs a router well under a millisecond, so latency cannot "
               "distinguish an honest hop from a tampering one. This is recorded for "
               "correlation only.",
               [f"median = {median:.0f} ms", f"spread = {spread:.0f} ms",
                f"samples = {len(samples)}"])]


def run_hygiene(client: RouterClient, sample_headers: dict[str, str] | None = None,
                latencies: list[float] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    findings += check_identity(client)
    findings += check_redirects(client)
    findings += check_auth_enforcement(client)
    findings += check_models(client)
    findings += check_error_shape(client)
    findings += check_signatures(client)
    findings += check_tls(client)
    if sample_headers:
        findings += check_provider_headers(client, sample_headers)
    if latencies:
        findings += latency_finding(latencies)
    return findings
