import io
import json

from rich.console import Console

from phishtriage.analyze import analyze_file
from phishtriage.models import Finding, Severity, Verdict
from phishtriage.report import plain_summary, print_report, to_json, to_markdown


def test_plain_summary_lists_reasons():
    findings = [
        Finding("a", Severity.HIGH, "t", "d", plain="reason one"),
        Finding("b", Severity.LOW, "t", "d", plain="reason two"),
    ]
    text = plain_summary(Verdict.MALICIOUS, findings)
    assert "reason one and reason two" in text
    assert "Do not click" in text


def test_clean_summary_has_no_reasons():
    findings = [Finding("a", Severity.LOW, "t", "d", plain="minor thing")]
    assert "minor thing" not in plain_summary(Verdict.CLEAN, findings)


def test_json_and_markdown(samples):
    report = analyze_file(samples / "fake_invoice.eml")
    data = json.loads(to_json(report))
    assert data["verdict"] == "Malicious"
    assert data["findings"][0]["severity"] == "high"
    md = to_markdown(report)
    assert "**Verdict:** Malicious" in md
    assert "hxxp://paypal-invoice-center[.]example" in md  # defanged
    assert "T1566.002" in md


def test_terminal_output_escapes_attacker_markup(samples, tmp_path):
    raw = (samples / "clean_personal.eml").read_text()
    evil = tmp_path / "evil.eml"
    evil.write_text(raw.replace("Subject: Bake sale volunteers", "Subject: [bold red]hi[/] [link]"))
    buf = io.StringIO()
    print_report(analyze_file(evil), Console(file=buf, width=120))
    assert "[bold red]hi[/]" in buf.getvalue()
