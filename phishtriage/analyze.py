"""The full pipeline: parse -> extract -> check -> enrich -> score -> report."""

from __future__ import annotations

from pathlib import Path

from phishtriage import checks, extractor, parser, scoring
from phishtriage.enrich import EnrichConfig, enrich
from phishtriage.models import Report
from phishtriage.report import plain_summary


def analyze_file(path: str | Path, config: EnrichConfig | None = None) -> Report:
    """Analyze one .eml. Pass config=None for offline mode."""
    path = Path(path)
    email = parser.parse_file(path)
    iocs = extractor.extract(email)
    findings = checks.run_all(email, iocs)

    notes: list[str] = []
    if config is None:
        notes.append("Offline mode: threat-intel lookups were skipped.")
    else:
        intel_findings, intel_notes = enrich(iocs, config)
        findings += intel_findings
        notes += intel_notes

    findings = scoring.sort_findings(findings)
    total, verdict = scoring.score(findings)
    return Report(
        file=path.name,
        subject=email.subject,
        from_addr=email.from_addr,
        verdict=verdict,
        score=total,
        summary=plain_summary(verdict, findings),
        findings=findings,
        iocs=iocs,
        attachments=email.attachments,
        notes=notes,
    )
