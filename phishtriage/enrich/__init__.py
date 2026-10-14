"""Threat-intel enrichment. Failures never stop the analysis; they become notes."""

from __future__ import annotations

from dataclasses import dataclass

import requests

from phishtriage.enrich.cache import Cache
from phishtriage.enrich.urlhaus import URLhaus
from phishtriage.enrich.virustotal import RateLimited, VirusTotal
from phishtriage.models import Finding, IOCs, Severity

DEFAULT_MAX_LOOKUPS = 8  # per email, per service; VirusTotal's free tier allows 4/minute


@dataclass
class EnrichConfig:
    vt_api_key: str = ""
    urlhaus_auth_key: str = ""
    max_lookups: int = DEFAULT_MAX_LOOKUPS
    use_cache: bool = True


def enrich(
    iocs: IOCs,
    config: EnrichConfig,
    cache: Cache | None = None,
    session: requests.Session | None = None,
) -> tuple[list[Finding], list[str]]:
    cache = cache or Cache(enabled=config.use_cache)
    session = session or requests.Session()
    findings: list[Finding] = []
    notes: list[str] = []

    if config.vt_api_key:
        f, n = _virustotal(iocs, VirusTotal(config.vt_api_key, session), cache, config)
        findings += f
        notes += n
    else:
        notes.append("VirusTotal skipped: VT_API_KEY not set.")

    if config.urlhaus_auth_key:
        f, n = _urlhaus(iocs, URLhaus(config.urlhaus_auth_key, session), cache, config)
        findings += f
        notes += n
    else:
        notes.append("URLhaus skipped: URLHAUS_AUTH_KEY not set.")

    cache.save()
    return findings, notes


def _virustotal(iocs, vt: VirusTotal, cache: Cache, config: EnrichConfig):
    findings: list[Finding] = []
    notes: list[str] = []
    # Hashes and URLs are the most specific indicators, so look them up first.
    targets = (
        [("file", h) for h in iocs.hashes]
        + [("url", u) for u in iocs.urls]
        + [("domain", d) for d in iocs.domains]
        + [("ip", i) for i in iocs.ips]
    )
    if len(targets) > config.max_lookups:
        notes.append(
            f"VirusTotal: checked {config.max_lookups} of {len(targets)} indicators (lookup limit)."
        )
        targets = targets[: config.max_lookups]

    for kind, value in targets:
        key = f"vt:{kind}:{value}"
        result = cache.get(key)
        if result is None:
            try:
                result = vt.lookup(kind, value)
            except RateLimited:
                notes.append("VirusTotal rate limit reached; remaining lookups skipped.")
                break
            except (requests.RequestException, ValueError) as exc:
                notes.append(f"VirusTotal lookup failed for {value}: {type(exc).__name__}")
                continue
            cache.set(key, result)

        malicious = result.get("malicious", 0)
        if malicious == 0 and result.get("suspicious", 0) == 0:
            continue
        severity = Severity.CRITICAL if malicious >= 2 else Severity.MEDIUM
        label = {"file": "Attachment", "url": "URL", "domain": "Domain", "ip": "IP"}[kind]
        findings.append(
            Finding(
                check=f"intel.virustotal.{kind}",
                severity=severity,
                title=f"{label} flagged by VirusTotal",
                detail=(
                    f"{value}: {malicious} engines malicious, "
                    f"{result.get('suspicious', 0)} suspicious."
                ),
                plain=(
                    "security vendors have flagged "
                    + ("an attachment" if kind == "file" else f"{label.lower()} {value}")
                    + " as dangerous"
                ),
                mitre="T1566.001" if kind == "file" else "T1566.002",
            )
        )
    return findings, notes


def _urlhaus(iocs, uh: URLhaus, cache: Cache, config: EnrichConfig):
    findings: list[Finding] = []
    notes: list[str] = []
    urls = iocs.urls
    if len(urls) > config.max_lookups:
        notes.append(f"URLhaus: checked {config.max_lookups} of {len(urls)} URLs (lookup limit).")
        urls = urls[: config.max_lookups]

    for url in urls:
        key = f"urlhaus:{url}"
        result = cache.get(key)
        if result is None:
            try:
                result = uh.lookup(url)
            except (requests.RequestException, ValueError) as exc:
                notes.append(f"URLhaus lookup failed for {url}: {type(exc).__name__}")
                continue
            cache.set(key, result)
        if result.get("listed"):
            threat = result.get("threat") or "malware"
            findings.append(
                Finding(
                    check="intel.urlhaus",
                    severity=Severity.CRITICAL,
                    title="URL listed on URLhaus",
                    detail=f"{url} is a known {threat} URL (status: {result.get('status')}).",
                    plain="a link is on a public list of known malicious websites",
                    mitre="T1566.002",
                )
            )
    return findings, notes
