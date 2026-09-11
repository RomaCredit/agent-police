"""Rendering an AuditReport for humans and for machines."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import AttackClass, AuditReport, Finding, Severity, Verdict

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_LABEL = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "info",
}


def to_json(report: AuditReport, *, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, sort_keys=False)


def _verdict_table(report: AuditReport) -> Table:
    table = Table(title="Trials", title_justify="left", header_style="bold",
                  show_edge=False, pad_edge=False)
    table.add_column("probe")
    table.add_column("class")
    table.add_column("clean", justify="right")
    table.add_column("tampered", justify="right")
    table.add_column("refused", justify="right")
    table.add_column("no call", justify="right")
    table.add_column("error", justify="right")

    per_probe: dict[str, dict[str, Any]] = {}
    for observation in report.observations:
        row = per_probe.setdefault(
            observation.probe_id,
            {"class": observation.attack_class.value, Verdict.CLEAN: 0,
             Verdict.TAMPERED: 0, Verdict.NO_TOOL_CALL: 0, Verdict.ERROR: 0,
             Verdict.INCONCLUSIVE: 0, Verdict.SUSPICIOUS: 0, Verdict.REFUSED: 0},
        )
        row[observation.verdict] = row.get(observation.verdict, 0) + 1

    for probe_id, row in sorted(per_probe.items()):
        tampered = row[Verdict.TAMPERED]
        table.add_row(
            probe_id,
            row["class"],
            str(row[Verdict.CLEAN]),
            Text(str(tampered), style="bold red" if tampered else "dim"),
            str(row[Verdict.REFUSED]),
            str(row[Verdict.NO_TOOL_CALL]),
            str(row[Verdict.ERROR]),
        )
    return table


def _finding_panel(finding: Finding) -> Panel:
    style = SEVERITY_STYLE[finding.severity]
    header = Text()
    header.append(f" {SEVERITY_LABEL[finding.severity]} ", style=style)
    header.append(f"  {finding.attack_class.value}", style="bold")
    header.append(f"  confidence: {finding.confidence}", style="dim")

    body: list[Any] = [header, Text(""), Text(finding.summary)]
    if finding.evidence:
        body.append(Text(""))
        evidence = Text()
        for line in finding.evidence:
            evidence.append("  " + line + "\n", style="dim")
        body.append(evidence)
    if finding.remediation:
        body.append(Text("→ " + finding.remediation, style="bold"))

    return Panel(Group(*body), title=finding.title, title_align="left",
                 border_style=style.split()[-1] if "on" not in style else "red")


def render(report: AuditReport, console: Console | None = None,
           *, show_info: bool = False) -> None:
    console = console or Console()

    worst = report.worst
    duration = (report.finished_at or 0) - report.started_at
    head = Text()
    head.append("agent-police", style="bold")
    head.append(f"  {report.target}\n")
    head.append(f"wire: {report.wire_format}   model: {report.model}   "
                f"trials: {len(report.observations)}   {duration:.0f}s\n", style="dim")
    head.append("worst finding: ", style="dim")
    head.append(f" {SEVERITY_LABEL[worst]} ", style=SEVERITY_STYLE[worst])
    console.print(Panel(head, border_style="blue"))

    findings = report.sorted_findings()
    actionable = [f for f in findings if f.severity is not Severity.INFO]
    informational = [f for f in findings if f.severity is Severity.INFO]

    if actionable:
        console.print()
        for finding in actionable:
            console.print(_finding_panel(finding))
    else:
        console.print("\n[green]No finding above informational severity.[/green]")

    if show_info and informational:
        console.print("\n[dim]--- informational ---[/dim]")
        for finding in informational:
            console.print(_finding_panel(finding))

    if report.observations:
        console.print()
        console.print(_verdict_table(report))

    observable = [c for c in report.canaries if c.get("observable")]
    if observable:
        console.print(f"\n[dim]{len(observable)} observable canaries planted. "
                      f"AC-2 shows up later, not now - re-check with "
                      f"`agent-police canary check`.[/dim]")

    console.print(
        "\n[yellow]A clean run is not proof of a clean endpoint.[/yellow] "
        "Conditional delivery (AC-1.b) stays dormant until its trigger fires, and the "
        "trigger lives on the server. Widen coverage with [bold]agent-police campaign[/bold]."
    )


def render_inspection(results: list[dict[str, Any]], console: Console | None = None) -> None:
    """Render passive inspection of a command with no ground truth."""
    console = console or Console()
    if not results:
        console.print("[green]Nothing suspicious found in the supplied command.[/green]")
        return
    table = Table(show_edge=False, header_style="bold")
    table.add_column("severity")
    table.add_column("issue")
    table.add_column("detail")
    for item in results:
        severity = Severity(item["severity"])
        table.add_row(
            Text(SEVERITY_LABEL[severity], style=SEVERITY_STYLE[severity]),
            item["title"], item["detail"],
        )
    console.print(table)
