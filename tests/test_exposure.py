import pytest
from signalforge.exposure import (parse_csv, sample_assets, save_assets, list_assets, find_matches)
from signalforge.demo import demo_records


def test_sample_inventory_intersects_only_explicitly_declared_cves(tmp_path):
    assets = sample_assets()
    records = demo_records()
    matches = find_matches(records, assets)
    assert len(matches) == 2
    assert matches[0]["is_demo"]
    assert all(m["warning"].startswith("Inventory-declared") for m in matches)
    assert {m["declared_cve"] for m in matches} == {"CVE-2099-0001", "CVE-2099-0002"}
    db = tmp_path / "assets.db"
    assert save_assets(assets, db) == 3
    assert len(list_assets(db)) == 3


def test_csv_parser_rejects_malformed_or_untrusted_inventory():
    content = "asset_id,product,environment,internet_exposed,criticality,known_cves,owner\nA1,Lab VM,Lab,true,High,CVE-2099-0001,Analyst\n"
    assert parse_csv(content)[0].cves() == ("CVE-2099-0001",)
    for bad in (content.replace("CVE-2099-0001", "'; DROP TABLE assets"),
                content.replace("true", "maybe"),
                content + content.splitlines()[1] + "\n"):
        with pytest.raises(ValueError):
            parse_csv(bad)


def test_missing_cves_never_fuzzy_match_product_name():
    assets = sample_assets()
    from signalforge.models import ThreatRecord
    from signalforge.prioritize import score
    record = score(ThreatRecord("X", "Fictional VPN gateway", "Unit test", "https://example.com", "2026-10-01", "test"))
    assert find_matches([record], assets) == []
