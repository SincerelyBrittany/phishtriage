"""Turn findings into a 0-100 risk score and a verdict."""

from __future__ import annotations

from phishtriage.models import Finding, Severity, Verdict

WEIGHTS = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 25,
    Severity.MEDIUM: 15,
    Severity.LOW: 5,
    Severity.INFO: 0,
}

SUSPICIOUS_AT = 20
MALICIOUS_AT = 50

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def score(findings: list[Finding]) -> tuple[int, Verdict]:
    """Each check counts once, at its highest severity, so ten bad links don't
    outweigh everything else."""
    best: dict[str, int] = {}
    for f in findings:
        best[f.check] = max(best.get(f.check, 0), WEIGHTS[f.severity])
    total = min(100, sum(best.values()))
    return total, verdict_for(total)


def verdict_for(total: int) -> Verdict:
    if total >= MALICIOUS_AT:
        return Verdict.MALICIOUS
    if total >= SUSPICIOUS_AT:
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.severity))
