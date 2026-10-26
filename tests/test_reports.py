from signalforge.demo import demo_records
from signalforge.reports import digest, linkedin_template
from signalforge.covers import render_cover
from PIL import Image
from io import BytesIO


def test_digest_demo_label_and_sources():
    text = digest(demo_records())
    assert "TRAINING DATA ONLY" in text
    assert "https://example.com" in text
    assert "not CVSS" in text.lower() or "not CVSS" in text


def test_linkedin_demo_label():
    post = linkedin_template(demo_records())
    assert "synthetic" in post.lower()
    assert "Sources:" in post


def test_cover_valid_png():
    image = Image.open(BytesIO(render_cover("A source-backed cybersecurity briefing", demo=True)))
    assert image.size == (1200, 627)
    assert image.format == "PNG"


def test_recency_filter_with_fixture_clock():
    from datetime import datetime, timezone
    from signalforge.reports import recent
    items = demo_records()
    fixed = datetime.combine(__import__('datetime').date.today(), datetime.min.time(), timezone.utc)
    assert len(recent(items, 1, now=fixed)) == 2
    assert len(recent(items, 8, now=fixed)) == 4


def test_recency_excludes_future_records():
    from datetime import datetime, timezone
    from signalforge.models import ThreatRecord
    from signalforge.reports import recent
    record = ThreatRecord('future', 'Future story', 'Test', 'https://example.org', '2099-01-01', '')
    assert recent([record], now=datetime(2026, 10, 26, tzinfo=timezone.utc)) == []
