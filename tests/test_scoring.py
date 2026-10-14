from phishtriage.models import Finding, Severity, Verdict
from phishtriage.scoring import score, sort_findings


def f(check, sev):
    return Finding(check=check, severity=sev, title="t", detail="d")


def test_empty_is_clean():
    assert score([]) == (0, Verdict.CLEAN)


def test_each_check_counts_once():
    findings = [f("links.text_mismatch", Severity.MEDIUM)] * 10
    assert score(findings) == (15, Verdict.CLEAN)


def test_single_high_is_suspicious():
    assert score([f("auth.dmarc", Severity.HIGH)]) == (25, Verdict.SUSPICIOUS)


def test_threat_intel_hit_plus_signal_is_malicious():
    total, verdict = score([f("intel.urlhaus", Severity.CRITICAL), f("auth.spf", Severity.MEDIUM)])
    assert (total, verdict) == (55, Verdict.MALICIOUS)


def test_score_is_capped():
    findings = [f(f"c{i}", Severity.CRITICAL) for i in range(5)]
    assert score(findings)[0] == 100


def test_sort_puts_most_severe_first():
    ordered = sort_findings(
        [f("a", Severity.LOW), f("b", Severity.CRITICAL), f("c", Severity.HIGH)]
    )
    assert [x.check for x in ordered] == ["b", "c", "a"]
