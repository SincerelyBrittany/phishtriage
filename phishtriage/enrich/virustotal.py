"""VirusTotal v3 reputation lookups. URLs are looked up by ID, never submitted or visited."""

from __future__ import annotations

import base64

import requests

API = "https://www.virustotal.com/api/v3"
TIMEOUT = 10


class RateLimited(Exception):
    pass


class VirusTotal:
    def __init__(self, api_key: str, session: requests.Session | None = None):
        self.api_key = api_key
        self.session = session or requests.Session()

    def lookup(self, kind: str, value: str) -> dict:
        """kind is one of: url, domain, ip, file. Returns {"found", "malicious", "suspicious"}."""
        path = {
            "url": f"urls/{_url_id(value)}",
            "domain": f"domains/{value}",
            "ip": f"ip_addresses/{value}",
            "file": f"files/{value}",
        }[kind]
        resp = self.session.get(
            f"{API}/{path}", headers={"x-apikey": self.api_key}, timeout=TIMEOUT
        )
        if resp.status_code == 404:
            return {"found": False, "malicious": 0, "suspicious": 0}
        if resp.status_code == 429:
            raise RateLimited("VirusTotal rate limit reached")
        resp.raise_for_status()
        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "found": True,
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
        }


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
