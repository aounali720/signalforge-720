from datetime import date
import pytest
from signalforge.sources import parse_kev, parse_rss, safe_url, clean_text, enrich_epss
from signalforge.models import ThreatRecord


def test_parse_kev_date_and_fields():
    fixture = {"vulnerabilities": [
        {"cveID": "CVE-2026-12345", "dateAdded": "2026-10-20", "vulnerabilityName": "Example product vulnerability", "shortDescription": "Known exploit", "requiredAction": "Apply vendor mitigation", "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2020-99999", "dateAdded": "2020-01-01"},
    ]}
    records = parse_kev(fixture, days=30, today=date(2026, 10, 26))
    assert len(records) == 1
    assert records[0].ransomware and records[0].kev
    assert records[0].cve == "CVE-2026-12345"


def test_bad_kev_payload():
    with pytest.raises(ValueError):
        parse_kev({"items": []})


def test_rss_parsing_and_html_cleanup():
    feed = b'''<?xml version="1.0"?><rss version="2.0"><channel><title>Example</title><item>
        <title>Security patch for CVE-2026-11111</title>
        <link>https://example.org/security</link><description>&lt;p&gt;Vendor advisory&lt;/p&gt;</description>
        <pubDate>Mon, 26 Oct 2026 08:00:00 GMT</pubDate>
        </item></channel></rss>'''
    result = parse_rss(feed, "Test")
    assert result[0].cve == "CVE-2026-11111"
    assert result[0].summary == "Vendor advisory"
    assert result[0].published_at.startswith("2026-10-26")


def test_safe_urls():
    assert safe_url("javascript:alert(1)") == ""
    assert safe_url("https://user:password@example.com/") == ""
    assert safe_url("https://EXAMPLE.COM/article#section") == "https://example.com/article"


class EpssResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {"data": [{"cve": "CVE-2026-11111", "epss": "0.36"}]}


class EpssSession:
    def __init__(self):
        self.calls = 0

    def get(self, *args, **kwargs):
        self.calls += 1
        return EpssResponse()


def test_epss_enrichment():
    r = ThreatRecord("t", "Advisory", "Test", "https://example.com", "2026-10-26", "", cve="CVE-2026-11111", kev=True)
    session = EpssSession()
    out = enrich_epss(session, [r])
    assert out[0].epss == 0.36
    assert session.calls == 1
