from pathlib import Path

import pytest

from phishtriage.parser import parse_bytes

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture
def samples() -> Path:
    return SAMPLES


@pytest.fixture
def make_email():
    """Build a ParsedEmail from header lines and an optional body."""

    def _make(headers: str, body: str = "hello", html: bool = False):
        ctype = "text/html" if html else "text/plain"
        raw = f"{headers.strip()}\nContent-Type: {ctype}; charset=utf-8\n\n{body}\n"
        return parse_bytes(raw.encode())

    return _make
