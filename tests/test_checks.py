from phishtriage.checks import attachments, auth, links, lookalike, urgency
from phishtriage.extractor import extract
from phishtriage.models import Severity

PASS = (
    "Authentication-Results: mx.example.org; spf=pass; dkim=pass; dmarc=pass\n"
    "From: a@shop.example\n"
)


def checks_of(findings):
    return {f.check for f in findings}


def test_auth_failures(make_email):
    email = make_email(
        "Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\nFrom: a@x.example"
    )
    assert {"auth.dmarc", "auth.spf", "auth.dkim"} <= checks_of(auth.run(email, extract(email)))


def test_auth_only_trusts_topmost_header(make_email):
    email = make_email(
        "Authentication-Results: mx; spf=fail; dmarc=fail\n"
        "Authentication-Results: forged; spf=pass; dmarc=pass\n"
        "From: a@x.example"
    )
    assert "auth.dmarc" in checks_of(auth.run(email, extract(email)))


def test_auth_pass_and_reply_to_mismatch(make_email):
    email = make_email(PASS + "Reply-To: b@other.example")
    found = checks_of(auth.run(email, extract(email)))
    assert found == {"auth.reply_to_mismatch"}


def test_same_org_subdomains_are_not_mismatches(make_email):
    email = make_email(
        PASS + "Reply-To: help@support.shop.example\nReturn-Path: <b@mail.shop.example>"
    )
    assert auth.run(email, extract(email)) == []


def test_missing_auth_results(make_email):
    email = make_email("From: a@x.example")
    assert checks_of(auth.run(email, extract(email))) == {"auth.missing"}


def test_lookalike_classify():
    assert lookalike.classify("paypa1.com")[0] is Severity.HIGH
    assert lookalike.classify("rnicrosoft.com")[0] is Severity.HIGH
    assert lookalike.classify("paypall.com")[0] is Severity.HIGH
    assert lookalike.classify("paypal.secure-login.example")[0] is Severity.MEDIUM
    # Swapped characters inside a longer domain are still a disguise.
    assert lookalike.classify("micros0ft-support.example")[0] is Severity.HIGH
    assert lookalike.classify("secure.paypa1-billing.example")[0] is Severity.HIGH
    # A plain brand word in a longer domain stays medium.
    assert lookalike.classify("microsoft-support.example")[0] is Severity.MEDIUM
    assert lookalike.classify("xn--pypal-4ve.com")[0] is Severity.MEDIUM
    assert lookalike.classify("www.paypal.com") is None
    assert lookalike.classify("login.microsoftonline.com") is None
    assert lookalike.classify("phase.com") is None
    assert lookalike.classify("groups.io") is None


def test_link_text_mismatch(make_email):
    email = make_email(
        PASS, '<a href="http://evil.example/x">https://www.paypal.com/login</a>', html=True
    )
    assert "links.text_mismatch" in checks_of(links.run(email, extract(email)))


def test_matching_link_text_is_fine(make_email):
    email = make_email(
        PASS,
        '<a href="https://www.paypal.com/x">paypal.com</a> <a href="https://a.example">Click</a>',
        html=True,
    )
    assert links.run(email, extract(email)) == []


def test_userinfo_and_shortener(make_email):
    email = make_email(PASS, "go to http://paypal.com@evil.example/ or https://bit.ly/abc")
    assert {"links.userinfo", "links.shortener"} <= checks_of(links.run(email, extract(email)))


def test_attachment_classify():
    assert attachments.classify("invoice.pdf.exe")[0] is Severity.HIGH
    assert attachments.classify("setup.EXE")[0] is Severity.HIGH
    assert attachments.classify("statement.html")[0] is Severity.MEDIUM
    assert attachments.classify("Q3.xlsm")[0] is Severity.MEDIUM
    assert attachments.classify("photos.zip")[0] is Severity.LOW
    assert attachments.classify("report.pdf") is None
    assert attachments.classify("README") is None


def test_urgency_and_credentials(make_email):
    email = make_email(
        PASS + "Subject: Final notice",
        "Please verify your password immediately or your account will be closed.",
    )
    assert checks_of(urgency.run(email, extract(email))) == {
        "content.urgency",
        "content.credentials",
    }


def test_urgency_needs_word_boundaries(make_email):
    email = make_email(PASS + "Subject: hi", "The insurgent plot in chapter two.")
    assert urgency.run(email, extract(email)) == []
