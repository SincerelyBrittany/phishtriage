"""Render a Report as plain English, a terminal view, JSON or Markdown."""

from __future__ import annotations

import json

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from phishtriage.models import Finding, Report, Severity, Verdict

ADVICE = {
    Verdict.MALICIOUS: (
        "Do not click any links, open attachments or reply. "
        "Report it to your IT contact or email provider, then delete it."
    ),
    Verdict.SUSPICIOUS: (
        "Don't click links or open attachments until you confirm with the sender "
        "using a phone number or website you already know."
    ),
    Verdict.CLEAN: (
        "Still be careful with any unexpected request for money, passwords or personal details."
    ),
}

OPENING = {
    Verdict.MALICIOUS: "This email shows strong signs of phishing",
    Verdict.SUSPICIOUS: "This email has some warning signs",
    Verdict.CLEAN: "No strong signs of phishing were found",
}

VERDICT_STYLE = {
    Verdict.MALICIOUS: "bold red",
    Verdict.SUSPICIOUS: "bold yellow",
    Verdict.CLEAN: "bold green",
}
SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def plain_summary(verdict: Verdict, findings: list[Finding], max_reasons: int = 3) -> str:
    """A short explanation for the person who received the email. Expects findings
    sorted most severe first."""
    reasons: list[str] = []
    if verdict is not Verdict.CLEAN:
        for f in findings:
            if f.plain and f.plain not in reasons:
                reasons.append(f.plain)
            if len(reasons) == max_reasons:
                break

    text = OPENING[verdict]
    if reasons:
        joined = (
            reasons[0] if len(reasons) == 1 else ", ".join(reasons[:-1]) + " and " + reasons[-1]
        )
        text += f": {joined}"
    return f"{text}. {ADVICE[verdict]}"


def to_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2)


def to_markdown(report: Report) -> str:
    lines = [
        f"# PhishTriage report: {report.file}",
        "",
        f"**Verdict:** {report.verdict.value} ({report.score}/100)",
        "",
        f"- **Subject:** {_md(report.subject)}",
        f"- **From:** {_md(report.from_addr)}",
        "",
        "## Summary",
        "",
        report.summary,
        "",
        "## Findings",
        "",
    ]
    if report.findings:
        lines += ["| Severity | Finding | Detail | MITRE ATT&CK |", "| --- | --- | --- | --- |"]
        for f in report.findings:
            lines.append(f"| {f.severity.value} | {_md(f.title)} | {_md(f.detail)} | {f.mitre} |")
    else:
        lines.append("No findings.")

    lines += ["", "## Indicators", ""]
    for label, items in (
        ("URLs", report.iocs.urls),
        ("Domains", report.iocs.domains),
        ("IPs", report.iocs.ips),
    ):
        lines.append(f"**{label}** ({len(items)})")
        lines.append("")
        lines += [f"- `{_defang(i)}`" for i in items] or ["- none"]
        lines.append("")
    lines.append(f"**Attachments** ({len(report.attachments)})")
    lines.append("")
    lines += [
        f"- `{_md(a.filename)}` ({a.content_type}, {a.size} bytes) SHA-256 `{a.sha256}`"
        for a in report.attachments
    ] or ["- none"]

    if report.notes:
        lines += ["", "## Notes", ""] + [f"- {n}" for n in report.notes]
    return "\n".join(lines) + "\n"


def print_report(report: Report, console: Console) -> None:
    style = VERDICT_STYLE[report.verdict]
    header = (
        f"[{style}]{report.verdict.value.upper()}[/]  (score {report.score}/100)\n"
        f"[dim]File:[/] {escape(report.file)}\n"
        f"[dim]From:[/] {escape(report.from_addr)}\n"
        f"[dim]Subject:[/] {escape(report.subject)}"
    )
    console.print(Panel(header, title="PhishTriage", border_style=style.split()[-1]))
    console.print(f"[bold]Summary[/]  {escape(report.summary)}\n")

    if report.findings:
        table = Table(title="Key findings", show_lines=False, title_justify="left")
        table.add_column("Severity")
        table.add_column("Finding")
        table.add_column("Detail", overflow="fold")
        table.add_column("ATT&CK")
        for f in report.findings:
            table.add_row(
                f"[{SEVERITY_STYLE[f.severity]}]{f.severity.value}[/]",
                escape(f.title),
                escape(f.detail),
                f.mitre,
            )
        console.print(table)

    i = report.iocs
    console.print(
        f"[dim]Indicators: {len(i.urls)} URLs, {len(i.domains)} domains, "
        f"{len(i.ips)} IPs, {len(i.hashes)} attachment hashes[/]"
    )
    for note in report.notes:
        console.print(f"[dim]Note: {escape(note)}[/]")
    console.print()


def _md(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("|", "\\|")
        .replace("\n", " ")
    )


def _defang(value: str) -> str:
    """Make indicators non-clickable in rendered Markdown."""
    return value.replace("http", "hxxp", 1).replace(".", "[.]")
