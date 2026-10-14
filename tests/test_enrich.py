import re

import pytest
import requests
import responses

from phishtriage.enrich import EnrichConfig, enrich
from phishtriage.enrich.cache import Cache
from phishtriage.models import IOCs, Severity

VT = re.compile(r"https://www\.virustotal\.com/api/v3/.*")
UH = "https://urlhaus-api.abuse.ch/v1/url/"


@pytest.fixture
def cache(tmp_path):
    return Cache(path=tmp_path / "cache.json")


def stats(malicious, suspicious=0):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": malicious, "suspicious": suspicious}
            }
        }
    }


@responses.activate
def test_flags_malicious_url(cache):
    responses.add(responses.GET, VT, json=stats(5))
    responses.add(
        responses.POST,
        UH,
        json={"query_status": "ok", "threat": "malware_download", "url_status": "online"},
    )
    iocs = IOCs(urls=["http://bad.example/x"])
    findings, notes = enrich(iocs, EnrichConfig("vt", "uh"), cache)
    checks = {f.check: f.severity for f in findings}
    assert checks["intel.virustotal.url"] is Severity.CRITICAL
    assert checks["intel.urlhaus"] is Severity.CRITICAL
    assert responses.calls[0].request.headers["x-apikey"] == "vt"
    assert responses.calls[1].request.headers["Auth-Key"] == "uh"


@responses.activate
def test_unknown_indicators_are_not_findings(cache):
    responses.add(responses.GET, VT, status=404)
    responses.add(responses.POST, UH, json={"query_status": "no_results"})
    findings, _ = enrich(
        IOCs(urls=["http://ok.example"], domains=["ok.example"]), EnrichConfig("vt", "uh"), cache
    )
    assert findings == []


@responses.activate
def test_rate_limit_stops_lookups_and_notes_it(cache):
    responses.add(responses.GET, VT, status=429)
    iocs = IOCs(domains=["a.example", "b.example"])
    findings, notes = enrich(iocs, EnrichConfig(vt_api_key="vt"), cache)
    assert findings == []
    assert len(responses.calls) == 1
    assert any("rate limit" in n for n in notes)


@responses.activate
def test_network_errors_do_not_crash(cache):
    responses.add(responses.GET, VT, body=requests.ConnectionError("boom"))
    findings, notes = enrich(IOCs(domains=["a.example"]), EnrichConfig(vt_api_key="vt"), cache)
    assert findings == []
    assert any("failed" in n for n in notes)


@responses.activate
def test_cache_prevents_repeat_lookups(tmp_path):
    responses.add(responses.GET, VT, json=stats(0))
    path = tmp_path / "cache.json"
    iocs = IOCs(domains=["a.example"])
    enrich(iocs, EnrichConfig(vt_api_key="vt"), Cache(path=path))
    enrich(iocs, EnrichConfig(vt_api_key="vt"), Cache(path=path))
    assert len(responses.calls) == 1


@responses.activate
def test_lookup_limit(cache):
    responses.add(responses.GET, VT, json=stats(0))
    iocs = IOCs(domains=[f"d{i}.example" for i in range(5)])
    _, notes = enrich(iocs, EnrichConfig(vt_api_key="vt", max_lookups=2), cache)
    assert len(responses.calls) == 2
    assert any("2 of 5" in n for n in notes)


def test_missing_keys_skip_with_notes(cache):
    findings, notes = enrich(IOCs(urls=["http://x.example"]), EnrichConfig(), cache)
    assert findings == []
    assert len(notes) == 2
