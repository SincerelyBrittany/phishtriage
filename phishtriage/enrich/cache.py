"""Tiny JSON file cache so repeat lookups don't burn free-tier API quota."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

DEFAULT_TTL = 24 * 60 * 60  # 1 day


def default_path() -> Path:
    base = os.environ.get("PHISHTRIAGE_CACHE_DIR") or Path.home() / ".cache" / "phishtriage"
    return Path(base) / "cache.json"


class Cache:
    def __init__(self, path: Path | None = None, ttl: int = DEFAULT_TTL, enabled: bool = True):
        self.path = path or default_path()
        self.ttl = ttl
        self.enabled = enabled
        self._data: dict[str, dict] = {}
        if enabled and self.path.exists():
            try:
                self._data = json.loads(self.path.read_text())
            except (OSError, ValueError):
                self._data = {}

    def get(self, key: str) -> dict | None:
        if not self.enabled:
            return None
        entry = self._data.get(key)
        if not entry or time.time() - entry.get("ts", 0) > self.ttl:
            return None
        return entry.get("value")

    def set(self, key: str, value: dict) -> None:
        if not self.enabled:
            return
        self._data[key] = {"ts": time.time(), "value": value}

    def save(self) -> None:
        if not self.enabled:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._data))
        except OSError:
            pass  # caching is best-effort
