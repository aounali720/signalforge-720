from signalforge.database import upsert, list_threats, save_triage
from signalforge.models import ThreatRecord
from signalforge.prioritize import score


def test_upsert_preserves_analyst_decisions(tmp_path):
    path = tmp_path / "sample.db"
    threat = score(ThreatRecord("same", "Original", "Test", "https://example.org", "2026-10-01", "text", kev=True))
    assert upsert([threat], path) == 1
    assert save_triage("same", "Investigating", "Review VPN inventory", path)
    threat.title = "Updated"
    upsert([threat], path)
    result = list_threats(path)
    assert len(result) == 1
    assert result[0].title == "Updated"
    assert result[0].status == "Investigating"
    assert result[0].analyst_notes == "Review VPN inventory"
    assert len(list_threats(path, search="Updated", priority="High")) == 1
    assert len(list_threats(path, search="NoMatch")) == 0


def test_status_whitelist(tmp_path):
    from pytest import raises
    with raises(ValueError):
        save_triage("x", "' OR 1=1 --", "oops", tmp_path / "x.db")


def test_demo_filter(tmp_path):
    from signalforge.demo import demo_records
    path = tmp_path / "demo.db"
    upsert(demo_records(), path)
    assert len(list_threats(path, demo=True)) == 4
    assert not list_threats(path, demo=False)
