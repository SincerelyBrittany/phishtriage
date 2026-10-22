import json

from typer.testing import CliRunner

from phishtriage.cli import app

runner = CliRunner()

EXPECTED = {
    "fake_invoice.eml": "Malicious",
    "credential_harvest.eml": "Malicious",
    "html_attachment.eml": "Suspicious",
    "clean_newsletter.eml": "Clean",
    "clean_personal.eml": "Clean",
}


def test_every_sample_gets_expected_verdict(samples):
    for name, verdict in EXPECTED.items():
        result = runner.invoke(app, ["analyze", str(samples / name), "--offline", "-f", "json"])
        assert json.loads(result.stdout)["verdict"] == verdict, name


def test_exit_codes(samples):
    assert (
        runner.invoke(app, ["analyze", str(samples / "clean_personal.eml"), "--offline"]).exit_code
        == 0
    )
    assert (
        runner.invoke(app, ["analyze", str(samples / "html_attachment.eml"), "--offline"]).exit_code
        == 1
    )
    assert (
        runner.invoke(app, ["analyze", str(samples / "fake_invoice.eml"), "--offline"]).exit_code
        == 2
    )


def test_folder_writes_one_report_per_email(samples, tmp_path):
    result = runner.invoke(
        app, ["analyze", str(samples), "--offline", "-f", "json", "-o", str(tmp_path)]
    )
    assert result.exit_code == 2  # worst verdict in the folder
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(
        n.replace(".eml", ".json") for n in EXPECTED
    )


def test_folder_json_to_stdout_is_an_array(samples):
    result = runner.invoke(app, ["analyze", str(samples), "--offline", "-f", "json"])
    assert len(json.loads(result.stdout)) == len(EXPECTED)


def test_no_keys_falls_back_gracefully(samples, monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)
    monkeypatch.chdir(samples)  # no .env here
    result = runner.invoke(app, ["analyze", "clean_personal.eml", "-f", "json"])
    assert any("VT_API_KEY not set" in n for n in json.loads(result.stdout)["notes"])


def test_empty_folder_errors(tmp_path):
    assert runner.invoke(app, ["analyze", str(tmp_path)]).exit_code == 3


def test_version():
    result = runner.invoke(app, ["--version"])
    assert "phishtriage" in result.stdout
