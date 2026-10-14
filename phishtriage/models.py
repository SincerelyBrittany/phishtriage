"""Data structures shared across the pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Verdict(str, Enum):
    CLEAN = "Clean"
    SUSPICIOUS = "Suspicious"
    MALICIOUS = "Malicious"


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str


@dataclass
class ParsedEmail:
    subject: str
    from_addr: str
    reply_to: str
    return_path: str
    to: str
    date: str
    message_id: str
    headers: list[tuple[str, str]]
    text_body: str
    html_body: str
    attachments: list[Attachment] = field(default_factory=list)

    def get_all(self, name: str) -> list[str]:
        """Return every value for a header, case-insensitive."""
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]


@dataclass
class IOCs:
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)


@dataclass
class Finding:
    check: str
    severity: Severity
    title: str
    detail: str
    # Short phrase for the plain-English summary, e.g. "the sender's identity check failed".
    plain: str = ""
    # MITRE ATT&CK technique, e.g. "T1566.002" (Spearphishing Link).
    mitre: str = "T1566"


@dataclass
class Report:
    file: str
    subject: str
    from_addr: str
    verdict: Verdict
    score: int
    summary: str
    findings: list[Finding]
    iocs: IOCs
    attachments: list[Attachment]
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["verdict"] = self.verdict.value
        for f in data["findings"]:
            f["severity"] = f["severity"].value
        return data
