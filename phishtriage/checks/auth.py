"""Sender authentication: SPF, DKIM, DMARC results and header mismatches."""

from __future__ import annotations

import re

from phishtriage.extractor import email_domain, registrable_domain
from phishtriage.models import Finding, IOCs, ParsedEmail, Severity

RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)


def auth_results(email: ParsedEmail) -> dict[str, str]:
    """Read spf/dkim/dmarc results from the topmost Authentication-Results header.

    The topmost header is the one added by the receiving server; lower ones could
    have been written by the sender and can't be trusted.
    """
    results: dict[str, str] = {}
    headers = email.get_all("Authentication-Results")
    if headers:
        for mech, value in RESULT_RE.findall(headers[0]):
            results.setdefault(mech.lower(), value.lower())
    if "spf" not in results:
        received_spf = email.get_all("Received-SPF")
        if received_spf:
            results["spf"] = received_spf[0].split()[0].lower()
    return results


def run(email: ParsedEmail, iocs: IOCs) -> list[Finding]:
    findings: list[Finding] = []
    results = auth_results(email)

    if not results:
        findings.append(
            Finding(
                check="auth.missing",
                severity=Severity.LOW,
                title="No authentication results",
                detail="No Authentication-Results or Received-SPF header was found.",
                plain="the email has no record of passing sender checks",
            )
        )

    dmarc = results.get("dmarc")
    if dmarc == "fail":
        findings.append(
            Finding(
                check="auth.dmarc",
                severity=Severity.HIGH,
                title="DMARC failed",
                detail="The sender domain's DMARC policy check failed.",
                plain="it failed the check that confirms who sent it (DMARC)",
            )
        )

    spf = results.get("spf")
    if spf in ("fail", "permerror"):
        findings.append(
            Finding(
                check="auth.spf",
                severity=Severity.MEDIUM,
                title=f"SPF {spf}",
                detail="The sending server is not authorized to send for this domain.",
                plain="it was sent from a server not allowed to send for that domain",
            )
        )
    elif spf == "softfail":
        findings.append(
            Finding(
                check="auth.spf",
                severity=Severity.LOW,
                title="SPF softfail",
                detail="The sending server is probably not authorized for this domain.",
                plain="the sending server is probably not allowed to send for that domain",
            )
        )

    if results.get("dkim") in ("fail", "permerror"):
        findings.append(
            Finding(
                check="auth.dkim",
                severity=Severity.MEDIUM,
                title="DKIM failed",
                detail="The message signature is invalid or was altered in transit.",
                plain="its digital signature didn't check out",
            )
        )

    findings.extend(_mismatches(email))
    return findings


def _mismatches(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    from_dom = email_domain(email.from_addr)
    if not from_dom:
        return findings
    from_org = registrable_domain(from_dom)

    reply_dom = email_domain(email.reply_to)
    if reply_dom and registrable_domain(reply_dom) != from_org:
        findings.append(
            Finding(
                check="auth.reply_to_mismatch",
                severity=Severity.MEDIUM,
                title="Reply-To differs from From",
                detail=f"From is {from_dom} but replies go to {reply_dom}.",
                plain=f"replies would go to {reply_dom}, not the sender's domain",
            )
        )

    return_dom = email_domain(email.return_path)
    if return_dom and registrable_domain(return_dom) != from_org:
        # Common for legitimate newsletters sent through a mailing service, so low weight.
        findings.append(
            Finding(
                check="auth.return_path_mismatch",
                severity=Severity.LOW,
                title="Return-Path differs from From",
                detail=f"From is {from_dom} but bounces go to {return_dom}.",
                plain="the hidden return address doesn't match the sender",
            )
        )
    return findings
