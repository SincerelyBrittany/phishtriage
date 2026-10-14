"""Parse a raw .eml into a ParsedEmail.

The input is attacker-controlled, so this module only reads bytes: attachments are
hashed, never decoded into files or opened.
"""

from __future__ import annotations

import hashlib
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path

from phishtriage.models import Attachment, ParsedEmail

MAX_EMAIL_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_BODY_CHARS = 1_000_000


class EmailTooLargeError(ValueError):
    pass


def parse_file(path: str | Path) -> ParsedEmail:
    path = Path(path)
    size = path.stat().st_size
    if size > MAX_EMAIL_BYTES:
        raise EmailTooLargeError(f"{path.name} is {size} bytes (limit {MAX_EMAIL_BYTES})")
    return parse_bytes(path.read_bytes())


def parse_bytes(raw: bytes) -> ParsedEmail:
    if len(raw) > MAX_EMAIL_BYTES:
        raise EmailTooLargeError(f"email is {len(raw)} bytes (limit {MAX_EMAIL_BYTES})")

    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)

    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[Attachment] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        ctype = part.get_content_type()

        if disposition == "attachment" or filename:
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                Attachment(
                    filename=filename or "(unnamed)",
                    content_type=ctype,
                    size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                )
            )
        elif ctype == "text/plain":
            text_parts.append(_safe_text(part))
        elif ctype == "text/html":
            html_parts.append(_safe_text(part))

    return ParsedEmail(
        subject=_header(msg, "Subject"),
        from_addr=_header(msg, "From"),
        reply_to=_header(msg, "Reply-To"),
        return_path=_header(msg, "Return-Path"),
        to=_header(msg, "To"),
        date=_header(msg, "Date"),
        message_id=_header(msg, "Message-ID"),
        headers=[(k, str(v)) for k, v in msg.items()],
        text_body="\n".join(text_parts)[:MAX_BODY_CHARS],
        html_body="\n".join(html_parts)[:MAX_BODY_CHARS],
        attachments=attachments,
    )


def _header(msg: EmailMessage, name: str) -> str:
    try:
        value = msg.get(name)
    except Exception:  # malformed headers shouldn't stop the analysis
        return ""
    return str(value).strip() if value is not None else ""


def _safe_text(part: EmailMessage) -> str:
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")
