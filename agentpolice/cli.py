"""Command-line interface."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from rich.console import Console

from . import __version__
from .canary import HostedCanaryProvider, LocalCanaryProvider, NullCanaryProvider
from .detect.inspect import inspect_command
from .models import AttackClass, SessionFingerprint
from .probes import registry
from .report import render, render_inspection, to_json
from .runner import AuditConfig, Auditor

KEY_ENV = "AGENT_POLICE_API_KEY"
DEFAULT_DB = Path(os.environ.get("AGENT_POLICE_HOME", Path.home() / ".agent-police")) / "canaries.db"

CLASS_ALIASES = {
    "ac1": AttackClass.AC1, "ac1a": AttackClass.AC1A,
    "ac1b": AttackClass.AC1B, "ac2": AttackClass.AC2,
}


def resolve_key(args) -> str:
    if args.key:
        return args.key
    env = os.environ.get(KEY_ENV)
    if env:
        return env
    if not sys.stdin.isatty():
        raise SystemExit(
            f"No API key. Pass --key, set {KEY_ENV}, or run interactively to be prompted."
        )
    return getpass.getpass("API key for the endpoint under test (not echoed): ")


def collector_is_remote(base_url: str | None) -> bool:
    """True when the canary base is a collector on some other host.

    A local SQLite store cannot see a callback that arrives at a collector
    elsewhere, so a remote base means the tokens have to be registered there
    or the whole AC-2 path is inert.
    """
    if not base_url:
        return False
    parts = urlsplit(base_url)
    if parts.scheme not in ("http", "https"):
        return False
    host = (parts.hostname or "").lower()
    return host not in ("", "localhost", "127.0.0.1", "::1")


def build_canary_provider(args, audit_id: str):
    if args.no_canary:
        return NullCanaryProvider(), None
    if collector_is_remote(args.canary_base):
        return HostedCanaryProvider(args.canary_base, args.canary_dns, audit_id), None
    from .store import SqliteCanaryStore
    store = SqliteCanaryStore(args.canary_db)
    return LocalCanaryProvider(args.canary_base, args.canary_dns, store), store


def parse_classes(raw: str | None) -> list[AttackClass]:
    if not raw:
        return [AttackClass.AC1, AttackClass.AC1A, AttackClass.AC2]
    out = []
    for token in raw.split(","):
        key = token.strip().lower().replace("-", "").replace(".", "")
        if key not in CLASS_ALIASES:
            raise SystemExit(f"unknown attack class {token!r}; expected ac1, ac1a, ac1b, ac2")
        out.append(CLASS_ALIASES[key])
    return out


def campaign_fingerprints(args) -> list[SessionFingerprint]:
    """The AC-1.b grid: vary the features a trigger predicate can key on."""
    tools = args.tools.split(",") if args.tools else ["Bash", "run_command"]
    langs = args.langs.split(",") if args.langs else ["rust", "go", "python", "javascript"]
    autonomies = ["yolo", "interactive"] if not args.yolo_only else ["yolo"]
    warmups = [int(w) for w in args.warmups.split(",")] if args.warmups else [0]

    grid: list[SessionFingerprint] = []
    for warmup in warmups:
        for autonomy in autonomies:
            for lang in langs:
                for tool in tools:
                    grid.append(SessionFingerprint(
                        tool_name=tool.strip(), project_lang=lang.strip(),
                        autonomy=autonomy, warmup_index=warmup,
                    ))
    return grid


def add_target_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("base_url", help="Endpoint under test, e.g. https://relay.example/v1")
    parser.add_argument("--key", "-k", help=f"API key (or set {KEY_ENV})")
    parser.add_argument("--model", "-m", required=True, help="Model id to request")
    parser.add_argument("--wire", "-w", default="anthropic", choices=["anthropic", "openai"],
                        help="Wire format the endpoint speaks (default: anthropic)")
    parser.add_argument("--repeats", "-r", type=int, default=2,
                        help="Distinct nonces per probe; 2+ enables stability scoring")
    parser.add_argument("--rate", type=float, default=20.0,
                        help="Max requests per minute (default: 20)")
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates")
    parser.add_argument("--no-hygiene", action="store_true", help="Skip endpoint hygiene checks")
    parser.add_argument("--no-canary", action="store_true", help="Do not plant AC-2 canaries")
    parser.add_argument("--canary-base", default=os.environ.get(
        "AGENT_POLICE_CANARY_BASE", "https://security.romaapi.com"))
    parser.add_argument("--canary-dns", default=os.environ.get("AGENT_POLICE_CANARY_DNS"))
    parser.add_argument("--canary-db", default=str(DEFAULT_DB))
    parser.add_argument("--json", dest="as_json", action="store_true", help="Emit JSON only")
    parser.add_argument("--out", help="Write the JSON report to this path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show informational findings")


def run_audit(args, fingerprints, classes, probe_ids=None) -> int:
    console = Console(stderr=args.as_json)
    key = resolve_key(args)
    audit_id = f"cli-{uuid.uuid4().hex[:12]}"
    provider, store = build_canary_provider(args, audit_id)

    config = AuditConfig(
        base_url=args.base_url, api_key=key, model=args.model, wire_name=args.wire,
        repeats=args.repeats, rate_per_minute=args.rate, timeout=args.timeout,
        verify_tls=not args.insecure, classes=classes, probe_ids=probe_ids,
        fingerprints=fingerprints, skip_hygiene=args.no_hygiene,
    )
    auditor = Auditor(config, provider)

    with console.status("[bold]probing[/bold]") as status:
        def progress(label: str, done: int, total: int) -> None:
            status.update(f"[bold]probing[/bold] {done}/{total}  {label}")
        report = auditor.run(progress)

    if isinstance(provider, HostedCanaryProvider):
        provider.flush()
        if provider.error:
            # Say it plainly: an audit whose canaries cannot be observed has
            # no AC-2 coverage, and a report that implies otherwise is worse
            # than one that admits the gap.
            report.notes.append(
                f"AC-2 COVERAGE LOST: could not register canaries with "
                f"{args.canary_base} ({provider.error}). Planted canaries will not be "
                f"recorded if they are used."
            )
            console.print(f"[bold red]AC-2 coverage lost:[/bold red] canary registration "
                          f"with {args.canary_base} failed ({provider.error}).")
        else:
            report.notes.append(
                f"{provider.registered} canaries registered with {args.canary_base}")
    elif store is not None:
        for canary in report.canaries:
            found = store.lookup(canary["token"])
            if found:
                store.register(found, audit_id)
    report.notes.append(f"canary audit id: {audit_id}")

    payload = to_json(report)
    if args.out:
        Path(args.out).write_text(payload, encoding="utf-8")
        console.print(f"[dim]report written to {args.out}[/dim]")
    if args.as_json:
        print(payload)
    else:
        render(report, console, show_info=args.verbose)

    worst = report.worst.value
    return 2 if worst in ("critical", "high") else (1 if worst == "medium" else 0)


def cmd_audit(args) -> int:
    return run_audit(args, [SessionFingerprint()], parse_classes(args.classes), args.probes)


def cmd_campaign(args) -> int:
    classes = parse_classes(args.classes or "ac1,ac1a")
    return run_audit(args, campaign_fingerprints(args), classes, args.probes)


def cmd_inspect(args) -> int:
    command = args.command or sys.stdin.read()
    results = inspect_command(command)
    if args.as_json:
        print(json.dumps(results, indent=2))
    else:
        render_inspection(results)
    return 2 if any(r["severity"] == "high" for r in results) else 0


def cmd_probes(args) -> int:
    console = Console()
    for probe in sorted(registry.values(), key=lambda p: (p.attack_class.value, p.id)):
        console.print(f"[bold]{probe.id}[/bold]  [dim]{probe.attack_class.value}[/dim]")
        console.print(f"   {probe.title} - {probe.description}")
    return 0


def _hosted_hits(base_url: str, audit_id: str, console: Console):
    """Ask a remote collector what it has seen for one audit."""
    import httpx

    from .canary import CanaryHit
    try:
        response = httpx.get(f"{base_url.rstrip('/')}/api/canary/{audit_id}", timeout=15.0)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        console.print(f"[red]Could not reach the collector at {base_url}: "
                      f"{type(exc).__name__}: {exc}[/red]")
        return None
    if not payload.get("planted"):
        console.print(f"[yellow]The collector has no canaries registered for "
                      f"{audit_id}.[/yellow] [dim]Nothing planted under this id would be "
                      f"recorded even if it were used.[/dim]")
    return [CanaryHit(h["token"], h["kind"], h["at"], h.get("source_ip"),
                      h.get("user_agent"), h.get("detail", ""))
            for h in payload.get("hits", [])]


def cmd_canary(args) -> int:
    from .store import SqliteCanaryStore
    console = Console()

    if not args.audit_id:
        # Without an id there is nothing to look up, and printing "no hits"
        # would read as an all-clear for a query that was never made.
        console.print(
            "[yellow]Pass --audit-id to check a specific run.[/yellow] "
            "[dim]Each audit prints its id (cli-...) when it finishes; the collector "
            "files canaries under it.[/dim]"
        )
        return 1

    # A CLI audit against a remote collector keeps nothing locally, so the
    # answer has to come from the collector that issued the tokens.
    if collector_is_remote(args.canary_base):
        hits = _hosted_hits(args.canary_base, args.audit_id, console)
        if hits is None:
            return 1
        store = None
    else:
        store = SqliteCanaryStore(args.canary_db)
        hits = store.hits_for_audit(args.audit_id)

    if not hits:
        console.print("[green]No canary hits recorded.[/green] "
                      "[dim]Harvested credentials are often validated and resold before use, "
                      "so keep checking.[/dim]")
        return 0
    console.print("[bold red]Canary hits recorded - something used a credential that only "
                  "existed inside your probe traffic.[/bold red]\n")
    for hit in hits:
        if hit.kind == "dns":
            # The query reached us from a recursive resolver, not from whoever
            # asked it. Naming an IP as the caller here would be wrong.
            console.print(f"  dns canary {hit.token[:10]}... resolved via resolver "
                          f"{hit.source_ip} [dim](the resolver, not the looker-up)[/dim]")
        else:
            console.print(f"  {hit.kind} canary {hit.token[:10]}... fetched by {hit.source_ip} "
                          f"({hit.user_agent or 'no user-agent'})")
        canary = store.lookup(hit.token) if store is not None else None
        if canary:
            console.print(f"    planted in: {canary.placement}")
    return 2


def cmd_serve(args) -> int:
    # The web dependencies are an extra, so the common failure here is a plain
    # `pip install agent-police`. A bare ModuleNotFoundError sends people to
    # search for "fastapi" instead of to the one command that fixes it.
    try:
        from .server.app import STATIC_DIR, serve
    except ImportError as exc:
        print(f"agent-police serve needs the web extra: {exc}\n\n"
              "    pip install 'agent-police[server]'\n",
              file=sys.stderr)
        return 1

    if not (STATIC_DIR / "index.html").exists():
        print(f"the web UI is missing from this install ({STATIC_DIR}).\n"
              "Reinstall from PyPI, or run from a source checkout.\n",
              file=sys.stderr)
        return 1

    serve(host=args.host, port=args.port, canary_db=args.canary_db,
          canary_base=args.canary_base, canary_dns=args.canary_dns)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-police",
        description=(
            "Audit an LLM API router for tool-call tampering and credential exposure. "
            "Probe only endpoints you are authorised to test."
        ),
    )
    parser.add_argument("--version", action="version", version=f"agent-police {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="One-shot audit of an endpoint")
    add_target_args(audit)
    audit.add_argument("--classes", help="Comma-separated: ac1,ac1a,ac2 (default: all three)")
    audit.add_argument("--probes", nargs="*", help="Run only these probe ids")
    audit.set_defaults(func=cmd_audit)

    campaign = sub.add_parser(
        "campaign",
        help="Long-running AC-1.b sweep across session fingerprints and warm-up depths")
    add_target_args(campaign)
    campaign.add_argument("--classes")
    campaign.add_argument("--probes", nargs="*")
    campaign.add_argument("--tools", help="Comma-separated tool names (default: Bash,run_command)")
    campaign.add_argument("--langs", help="Comma-separated project languages")
    campaign.add_argument("--warmups", help="Comma-separated warm-up depths, e.g. 0,10,50")
    campaign.add_argument("--yolo-only", action="store_true",
                          help="Only probe auto-approve sessions")
    campaign.set_defaults(func=cmd_campaign)

    inspect = sub.add_parser("inspect", help="Heuristically review a command (no network)")
    inspect.add_argument("command", nargs="?", help="Command text; omit to read stdin")
    inspect.add_argument("--json", dest="as_json", action="store_true")
    inspect.set_defaults(func=cmd_inspect)

    probes = sub.add_parser("probes", help="List available probes")
    probes.set_defaults(func=cmd_probes)

    canary = sub.add_parser("canary", help="Check planted canaries for use")
    canary.add_argument("--canary-base", default=os.environ.get(
        "AGENT_POLICE_CANARY_BASE", "https://security.romaapi.com"),
        help="Collector that issued the canaries; queried when --audit-id is a hosted run")
    # Documented as `agent-police canary check`; accept the bare form too.
    canary.add_argument("action", nargs="?", default="check", choices=["check"],
                        help="check (default)")
    canary.add_argument("--audit-id", help="Only this audit's canaries")
    canary.add_argument("--canary-db", default=str(DEFAULT_DB))
    canary.set_defaults(func=cmd_canary)

    serve = sub.add_parser("serve", help="Run the web service and canary collector")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--canary-db", default=str(DEFAULT_DB))
    serve.add_argument("--canary-base", default=os.environ.get(
        "AGENT_POLICE_CANARY_BASE", "https://security.romaapi.com"))
    serve.add_argument("--canary-dns", default=os.environ.get("AGENT_POLICE_CANARY_DNS"))
    serve.set_defaults(func=cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
