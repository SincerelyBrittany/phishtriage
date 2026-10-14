"""Command-line entry point."""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path

import typer
from dotenv import load_dotenv
from rich.console import Console

from phishtriage import __version__, report
from phishtriage.analyze import analyze_file
from phishtriage.enrich import DEFAULT_MAX_LOOKUPS, EnrichConfig
from phishtriage.models import Report, Verdict
from phishtriage.parser import EmailTooLargeError

app = typer.Typer(
    help="Analyze a suspicious email and tell you whether it's phishing, why, and what to do next.",
    add_completion=False,
    no_args_is_help=True,
)

EXIT_CODES = {Verdict.CLEAN: 0, Verdict.SUSPICIOUS: 1, Verdict.MALICIOUS: 2}
EXIT_ERROR = 3


class Format(str, Enum):
    text = "text"
    json = "json"
    md = "md"


def _version(value: bool) -> None:
    if value:
        typer.echo(f"phishtriage {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version, is_eager=True, help="Show version and exit."
    ),
) -> None:
    """PhishTriage."""


@app.command()
def analyze(
    path: Path = typer.Argument(..., exists=True, help="An .eml file or a folder of .eml files."),
    offline: bool = typer.Option(False, "--offline", help="Skip threat-intel lookups."),
    fmt: Format = typer.Option(Format.text, "--format", "-f", help="Output format."),
    out: Path | None = typer.Option(
        None, "--out", "-o", help="Write one report file per email into this folder."
    ),
    no_cache: bool = typer.Option(False, "--no-cache", help="Don't use the lookup cache."),
    max_lookups: int = typer.Option(
        DEFAULT_MAX_LOOKUPS, help="Max lookups per email per threat-intel service."
    ),
) -> None:
    """Analyze one email or a folder of emails.

    Exit code: 0 clean, 1 suspicious, 2 malicious (worst result), 3 error.
    """
    console = Console()
    err = Console(stderr=True)
    load_dotenv()

    files = sorted(path.glob("*.eml")) if path.is_dir() else [path]
    if not files:
        err.print(f"No .eml files found in {path}", style="red", markup=False)
        raise typer.Exit(EXIT_ERROR)

    config = None
    if not offline:
        config = EnrichConfig(
            vt_api_key=os.environ.get("VT_API_KEY", "").strip(),
            urlhaus_auth_key=os.environ.get("URLHAUS_AUTH_KEY", "").strip(),
            max_lookups=max_lookups,
            use_cache=not no_cache,
        )

    if out:
        out.mkdir(parents=True, exist_ok=True)

    worst = 0
    had_error = False
    json_reports: list[str] = []
    for file in files:
        try:
            result = analyze_file(file, config)
        except (OSError, EmailTooLargeError) as exc:
            err.print(f"Could not analyze {file.name}: {exc}", style="red", markup=False)
            had_error = True
            continue
        worst = max(worst, EXIT_CODES[result.verdict])

        if out:
            for written in _write(result, out, fmt):
                console.print(f"Wrote {written}", soft_wrap=True, highlight=False)
        elif fmt is Format.json:
            json_reports.append(report.to_json(result))
        elif fmt is Format.md:
            console.out(report.to_markdown(result), highlight=False)
        else:
            report.print_report(result, console)

    if json_reports:
        # One object for a single file, a JSON array for a folder.
        body = json_reports[0] if len(files) == 1 else "[\n" + ",\n".join(json_reports) + "\n]"
        console.out(body, highlight=False)

    raise typer.Exit(EXIT_ERROR if had_error and worst == 0 else worst)


def _write(result: Report, out: Path, fmt: Format) -> list[Path]:
    stem = Path(result.file).stem
    written: list[Path] = []
    if fmt in (Format.json, Format.text):
        p = out / f"{stem}.json"
        p.write_text(report.to_json(result))
        written.append(p)
    if fmt in (Format.md, Format.text):
        p = out / f"{stem}.md"
        p.write_text(report.to_markdown(result))
        written.append(p)
    return written
