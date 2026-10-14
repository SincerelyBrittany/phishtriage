"""Lookalike and brand-impersonation domains (paypa1.com, paypal.secure-login.ru)."""

from __future__ import annotations

import re

from phishtriage.extractor import email_domain, registrable_domain
from phishtriage.models import Finding, IOCs, ParsedEmail, Severity

# Brand -> domains the brand really uses.
BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me"},
    "microsoft": {
        "microsoft.com",
        "office.com",
        "live.com",
        "outlook.com",
        "microsoftonline.com",
        "office365.com",
        "sharepoint.com",
    },
    "office365": {"office.com", "office365.com", "microsoft.com"},
    "outlook": {"outlook.com", "live.com", "microsoft.com"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"icloud.com", "apple.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de", "amazonaws.com"},
    "google": {"google.com", "gmail.com", "youtube.com", "googleusercontent.com"},
    "gmail": {"gmail.com", "google.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "netflix": {"netflix.com"},
    "dropbox": {"dropbox.com"},
    "linkedin": {"linkedin.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com"},
    "wellsfargo": {"wellsfargo.com"},
    "chase": {"chase.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "coinbase": {"coinbase.com"},
    "venmo": {"venmo.com"},
    "zelle": {"zellepay.com"},
    "adobe": {"adobe.com"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
    "dhl": {"dhl.com"},
    "irs": {"irs.gov"},
}

# Character swaps attackers use to imitate letters.
HOMOGLYPHS = [
    ("rn", "m"),
    ("vv", "w"),
    ("0", "o"),
    ("1", "l"),
    ("3", "e"),
    ("5", "s"),
    ("4", "a"),
    ("7", "t"),
    ("8", "b"),
    ("$", "s"),
]

MIN_FUZZY_LEN = 6  # only fuzzy-match longer brands; "chase" vs "phase" is a real domain


def normalize(label: str) -> str:
    label = label.lower()
    for fake, real in HOMOGLYPHS:
        label = label.replace(fake, real)
    return label


def edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _legit(host: str) -> bool:
    org = registrable_domain(host)
    return any(org in domains for domains in BRANDS.values())


def classify(host: str) -> tuple[Severity, str] | None:
    """Return (severity, reason) if host looks like brand impersonation."""
    host = host.lower().rstrip(".")
    if not host or _legit(host):
        return None

    if "xn--" in host:
        return Severity.MEDIUM, "uses punycode, which can hide lookalike characters"

    org = registrable_domain(host)
    label = org.split(".")[0]
    norm = normalize(label)
    for brand in BRANDS:
        if norm == brand and label != brand:
            return Severity.HIGH, f"imitates {brand} by swapping characters"
        if label == brand:
            return Severity.HIGH, f"uses the {brand} name on a domain {brand} doesn't own"
        if len(brand) >= MIN_FUZZY_LEN and edit_distance(norm, brand) == 1:
            return Severity.HIGH, f"is one letter off from {brand}"

    tokens = [normalize(t) for t in re.split(r"[.\-_]", host) if t]
    for brand in BRANDS:
        if len(brand) >= 4 and brand in tokens:
            return Severity.MEDIUM, f"contains the {brand} name but isn't a {brand} domain"
    return None


def run(email: ParsedEmail, iocs: IOCs) -> list[Finding]:
    findings: list[Finding] = []
    sender_hosts = {email_domain(email.from_addr), email_domain(email.reply_to)} - {""}
    seen: set[str] = set()

    for host in [*sender_hosts, *iocs.domains]:
        if host in seen:
            continue
        seen.add(host)
        result = classify(host)
        if not result:
            continue
        severity, reason = result
        is_sender = host in sender_hosts
        findings.append(
            Finding(
                check=f"lookalike.{'sender' if is_sender else 'link'}",
                severity=severity,
                title=f"Lookalike {'sender' if is_sender else 'link'} domain: {host}",
                detail=f"{host} {reason}.",
                plain=(
                    f"the sender's address ({host}) {reason}"
                    if is_sender
                    else f"a link goes to {host}, which {reason}"
                ),
                mitre="T1566" if is_sender else "T1566.002",
            )
        )
    return findings
