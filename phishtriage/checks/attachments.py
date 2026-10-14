"""Risky attachment types. Attachments are only inspected by name, never opened."""

from __future__ import annotations

from pathlib import PurePosixPath

from phishtriage.models import Finding, IOCs, ParsedEmail, Severity

EXECUTABLE = {
    ".exe",
    ".scr",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".bat",
    ".cmd",
    ".ps1",
    ".msi",
    ".lnk",
    ".hta",
    ".jar",
    ".com",
    ".pif",
    ".wsf",
    ".cpl",
}
RISKY = {
    ".html",
    ".htm",
    ".shtml",
    ".svg",
    ".iso",
    ".img",
    ".vhd",
    ".vhdx",
    ".docm",
    ".xlsm",
    ".pptm",
    ".dotm",
    ".xlam",
    ".one",
}
ARCHIVE = {".zip", ".rar", ".7z", ".gz", ".tar", ".cab"}
DOCUMENT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png", ".csv"}


def classify(filename: str) -> tuple[Severity, str] | None:
    suffixes = [s.lower() for s in PurePosixPath(filename.strip()).suffixes]
    if not suffixes:
        return None
    last = suffixes[-1]
    if len(suffixes) >= 2 and suffixes[-2] in DOCUMENT and last in EXECUTABLE | RISKY:
        return Severity.HIGH, "uses a double extension to disguise its real type"
    if last in EXECUTABLE:
        return Severity.HIGH, "is a program or script that can run on your computer"
    if last in RISKY:
        return Severity.MEDIUM, "is a file type often used to deliver phishing pages or malware"
    if last in ARCHIVE:
        return Severity.LOW, "is a compressed archive that can hide its contents"
    return None


def run(email: ParsedEmail, iocs: IOCs) -> list[Finding]:
    findings: list[Finding] = []
    for att in email.attachments:
        result = classify(att.filename)
        if not result:
            continue
        severity, reason = result
        findings.append(
            Finding(
                check="attachment.risky_type",
                severity=severity,
                title=f"Risky attachment: {att.filename}",
                detail=f"{att.filename} ({att.content_type}) {reason}. SHA-256 {att.sha256}.",
                plain=f"the attachment {att.filename} {reason}",
                mitre="T1566.001",
            )
        )
    return findings
