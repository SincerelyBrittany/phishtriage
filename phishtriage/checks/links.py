"""Deceptive links: visible text that names a different site than the real destination."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from phishtriage.extractor import IPV4_RE, domain_of, html_links, registrable_domain
from phishtriage.models import Finding, IOCs, ParsedEmail, Severity

# Visible text that looks like a URL or bare domain, e.g. "www.paypal.com/login".
TEXT_DOMAIN_RE = re.compile(
    r"^(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]\S*)?$", re.IGNORECASE
)

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "rb.gy",
    "tiny.cc",
}


def run(email: ParsedEmail, iocs: IOCs) -> list[Finding]:
    findings: list[Finding] = []

    for href, text in html_links(email.html_body):
        match = TEXT_DOMAIN_RE.match(text.strip())
        dest = domain_of(href)
        if not match or not dest:
            continue
        shown = match.group(1).lower()
        if registrable_domain(shown) != registrable_domain(dest):
            findings.append(
                Finding(
                    check="links.text_mismatch",
                    severity=Severity.MEDIUM,
                    title="Link text doesn't match destination",
                    detail=f"Link shows {shown} but points to {dest}.",
                    plain=f"a link shows {shown} but actually goes to {dest}",
                    mitre="T1566.002",
                )
            )

    for url in iocs.urls:
        host = domain_of(url)
        if IPV4_RE.fullmatch(host):
            findings.append(
                Finding(
                    check="links.ip_host",
                    severity=Severity.MEDIUM,
                    title="Link points to a raw IP address",
                    detail=f"{url} uses an IP address instead of a domain name.",
                    plain="a link goes to a bare number address instead of a website name",
                    mitre="T1566.002",
                )
            )
        if _has_userinfo(url):
            findings.append(
                Finding(
                    check="links.userinfo",
                    severity=Severity.MEDIUM,
                    title="Link hides its destination with '@'",
                    detail=f"{url} puts text before '@' so the real host is {host}.",
                    plain=f"a link is disguised so it looks like another site but goes to {host}",
                    mitre="T1566.002",
                )
            )
        if host in SHORTENERS:
            findings.append(
                Finding(
                    check="links.shortener",
                    severity=Severity.LOW,
                    title="Link uses a URL shortener",
                    detail=f"{url} hides its final destination behind {host}.",
                    plain="a link uses a shortener that hides where it really goes",
                    mitre="T1566.002",
                )
            )
    return findings


def _has_userinfo(url: str) -> bool:
    try:
        return "@" in (urlsplit(url).netloc or "")
    except ValueError:
        return False
