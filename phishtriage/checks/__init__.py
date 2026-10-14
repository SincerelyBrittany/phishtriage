"""Offline checks. Each module exposes run(email, iocs) -> list[Finding]."""

from __future__ import annotations

from phishtriage.checks import attachments, auth, links, lookalike, urgency
from phishtriage.models import Finding, IOCs, ParsedEmail

CHECKS = [auth, lookalike, links, attachments, urgency]


def run_all(email: ParsedEmail, iocs: IOCs) -> list[Finding]:
    findings: list[Finding] = []
    for check in CHECKS:
        findings.extend(check.run(email, iocs))
    return findings
