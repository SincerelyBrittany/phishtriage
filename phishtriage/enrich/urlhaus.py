"""URLhaus (abuse.ch) known-malicious URL lookups."""

from __future__ import annotations

import requests

API = "https://urlhaus-api.abuse.ch/v1/url/"
TIMEOUT = 10


class URLhaus:
    def __init__(self, auth_key: str, session: requests.Session | None = None):
        self.auth_key = auth_key
        self.session = session or requests.Session()

    def lookup(self, url: str) -> dict:
        """Returns {"listed": bool, "threat": str, "status": str}."""
        resp = self.session.post(
            API, data={"url": url}, headers={"Auth-Key": self.auth_key}, timeout=TIMEOUT
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") != "ok":
            return {"listed": False, "threat": "", "status": ""}
        return {
            "listed": True,
            "threat": data.get("threat") or "",
            "status": data.get("url_status") or "",
        }
