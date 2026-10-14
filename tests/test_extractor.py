from phishtriage.extractor import (
    domain_of,
    email_domain,
    extract,
    html_links,
    registrable_domain,
)
from phishtriage.parser import parse_file


def test_extracts_urls_and_domains(samples):
    iocs = extract(parse_file(samples / "fake_invoice.eml"))
    assert iocs.urls == ["http://paypal-invoice-center.example/pay?id=88213"]
    assert "paypal-invoice-center.example" in iocs.domains
    assert "paypa1.example" in iocs.domains
    assert "mailbox-support.example" in iocs.domains


def test_ip_literal_hosts_are_ips_not_domains(make_email):
    email = make_email(
        "From: a@b.example\nReceived: from x (x [8.8.8.8]) by y",
        '<a href="http://1.1.1.1/login">x</a>',
        html=True,
    )
    iocs = extract(email)
    assert "1.1.1.1" in iocs.ips
    assert "8.8.8.8" in iocs.ips
    assert "1.1.1.1" not in iocs.domains


def test_private_ips_are_dropped(make_email):
    email = make_email("From: a@b.example\nReceived: from x ([10.0.0.5]) by y")
    assert extract(email).ips == []


def test_helpers():
    assert domain_of("https://Login.PayPal.com:443/x") == "login.paypal.com"
    assert email_domain('"Name" <user@Mail.Example.com>') == "mail.example.com"
    assert registrable_domain("mail.paypal.com") == "paypal.com"
    assert registrable_domain("shop.amazon.co.uk") == "amazon.co.uk"
    assert html_links('<a href="https://x.example">Click <b>here</b></a>') == [
        ("https://x.example", "Click here")
    ]
