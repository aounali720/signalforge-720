from signalforge.models import ThreatRecord
from signalforge.prioritize import score


def record(**kwargs):
    base = dict(key="a", title="Patch announced", source="Test", url="https://example.org", published_at="2026-10-01", summary="Routine bug")
    base.update(kwargs)
    return ThreatRecord(**base)


def test_kev_priority():
    result = score(record(kev=True, ransomware=True, epss=1.0))
    assert result.priority == "High"
    assert result.priority_score == 100
    assert "CISA" in result.rationale


def test_unconfirmed_news_not_kev():
    result = score(record(title="Zero-day remote code execution under investigation"))
    assert result.kev is False
    assert result.priority_score == 24  # one top keyword, not a sum of hype terms
    assert "unverified" in result.rationale


def test_empty_news_low():
    assert score(record()).priority_score == 0


def test_epss_is_bounded():
    assert score(record(kev=True, epss=99)).priority_score == 88
