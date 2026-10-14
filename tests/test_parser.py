import pytest

from phishtriage import parser
from phishtriage.parser import EmailTooLargeError, parse_bytes, parse_file


def test_parses_headers_and_bodies(samples):
    email = parse_file(samples / "fake_invoice.eml")
    assert email.subject.startswith("Invoice #INV-88213")
    assert "billing@paypa1.example" in email.from_addr
    assert "payments-desk@mailbox-support.example" in email.reply_to
    assert "overdue" in email.text_body
    assert "<a href=" in email.html_body
    assert len(email.get_all("Authentication-Results")) == 1


def test_attachment_is_hashed_not_saved(samples):
    email = parse_file(samples / "html_attachment.eml")
    assert len(email.attachments) == 1
    att = email.attachments[0]
    assert att.filename == "Fax_Document_0923.pdf.html"
    assert len(att.sha256) == 64
    assert att.size > 0
    assert "Synthetic attachment" not in email.html_body


def test_rejects_oversized_email(monkeypatch):
    monkeypatch.setattr(parser, "MAX_EMAIL_BYTES", 100)
    with pytest.raises(EmailTooLargeError):
        parse_bytes(b"Subject: x\n\n" + b"a" * 200)


def test_handles_garbage_input():
    email = parse_bytes(b"\x00\xff not an email at all")
    assert email.subject == ""
