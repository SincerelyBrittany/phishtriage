"""Extract indicators of compromise (URLs, domains, IPs, hashes) from a parsed email."""

from __future__ import annotations

import ipaddress
import re
from email.utils import getaddresses
from html.parser import HTMLParser
from urllib.parse import urlsplit

from phishtriage.models import IOCs, ParsedEmail

URL_RE = re.compile(r"""\bhttps?://[^\s<>"'()\[\]{}]+""", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
BRACKET_IP_RE = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")


class _LinkCollector(HTMLParser):
    """Collect (href, visible text) pairs from <a> tags."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href is not None:
            self.links.append((self._href.strip(), " ".join("".join(self._text).split())))
            self._href = None


def html_links(html: str) -> list[tuple[str, str]]:
    collector = _LinkCollector()
    try:
        collector.feed(html)
        collector.close()
    except Exception:
        pass
    return collector.links


def domain_of(url: str) -> str:
    """Hostname of a URL, lowercased, without port or trailing dot."""
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return ""
    return host.rstrip(".").lower()


# Common multi-part public suffixes. Not a full Public Suffix List, but enough to
# compare organizational domains without a network fetch.
MULTI_PART_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.nz",
    "co.jp",
    "co.in",
    "com.br",
    "com.mx",
    "co.za",
    "com.sg",
    "com.cn",
    "com.tr",
}


def registrable_domain(host: str) -> str:
    """Best-effort organizational domain: mail.paypal.com -> paypal.com."""
    host = host.rstrip(".").lower()
    if IPV4_RE.fullmatch(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def email_domain(header_value: str) -> str:
    """Domain part of the first address in an address header."""
    addrs = getaddresses([header_value]) if header_value else []
    for _, addr in addrs:
        if "@" in addr:
            return addr.rsplit("@", 1)[1].strip(">").rstrip(".").lower()
    return ""


def _clean_url(url: str) -> str:
    return url.rstrip(".,;:!?")


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global


def extract(email: ParsedEmail) -> IOCs:
    urls: list[str] = []
    for href, _ in html_links(email.html_body):
        if href.lower().startswith(("http://", "https://")):
            urls.append(_clean_url(href))
    for body in (email.text_body, email.html_body):
        urls.extend(_clean_url(u) for u in URL_RE.findall(body))
    urls = _dedupe(urls)

    domains = _dedupe(d for d in (domain_of(u) for u in urls) if d)
    sender_domains = (
        email_domain(email.from_addr),
        email_domain(email.reply_to),
        email_domain(email.return_path),
    )
    domains = _dedupe([*domains, *(d for d in sender_domains if d)])

    ips: list[str] = []
    for received in email.get_all("Received"):
        ips.extend(BRACKET_IP_RE.findall(received))
        ips.extend(IPV4_RE.findall(received))
    ips.extend(d for d in domains if IPV4_RE.fullmatch(d))
    ips = _dedupe(ip for ip in ips if _is_public_ip(ip))
    domains = [d for d in domains if not IPV4_RE.fullmatch(d)]

    hashes = _dedupe(a.sha256 for a in email.attachments)
    return IOCs(urls=urls, domains=domains, ips=ips, hashes=hashes)


def _dedupe(items) -> list[str]:
    seen: dict[str, None] = {}
    for item in items:
        seen.setdefault(item, None)
    return list(seen)
