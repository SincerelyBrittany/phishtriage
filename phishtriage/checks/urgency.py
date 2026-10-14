"""Pressure language and requests for credentials or money."""

from __future__ import annotations

import re

from phishtriage.models import Finding, IOCs, ParsedEmail, Severity

URGENCY_PHRASES = [
    "urgent",
    "immediately",
    "act now",
    "within 24 hours",
    "within 48 hours",
    "final notice",
    "final warning",
    "last chance",
    "account will be suspended",
    "account has been suspended",
    "account will be closed",
    "account has been locked",
    "unusual activity",
    "suspicious activity",
    "unauthorized access",
    "expires today",
    "failure to comply",
    "avoid suspension",
    "action required",
    "respond immediately",
]

CREDENTIAL_PHRASES = [
    "verify your account",
    "verify your identity",
    "confirm your identity",
    "confirm your password",
    "verify your password",
    "update your password",
    "enter your password",
    "login credentials",
    "sign in to verify",
    "log in to verify",
    "update your payment",
    "update your billing",
    "confirm your payment",
    "social security number",
    "bank account details",
    "gift card",
    "wire transfer",
]

TAG_RE = re.compile(r"<[^>]+>")


def _text(email: ParsedEmail) -> str:
    html_text = TAG_RE.sub(" ", email.html_body)
    return " ".join(f"{email.subject} {email.text_body} {html_text}".lower().split())


def _matches(text: str, phrases: list[str]) -> list[str]:
    return [p for p in phrases if re.search(rf"\b{re.escape(p)}\b", text)]


def run(email: ParsedEmail, iocs: IOCs) -> list[Finding]:
    text = _text(email)
    findings: list[Finding] = []

    urgency = _matches(text, URGENCY_PHRASES)
    if urgency:
        findings.append(
            Finding(
                check="content.urgency",
                severity=Severity.LOW,
                title="Urgency or pressure language",
                detail="Phrases: " + ", ".join(f'"{p}"' for p in urgency[:5]),
                plain="it tries to rush you into acting",
            )
        )

    creds = _matches(text, CREDENTIAL_PHRASES)
    if creds:
        findings.append(
            Finding(
                check="content.credentials",
                severity=Severity.LOW,
                title="Asks for credentials, payment or personal data",
                detail="Phrases: " + ", ".join(f'"{p}"' for p in creds[:5]),
                plain="it asks for your login, payment or personal details",
            )
        )
    return findings
