from datetime import datetime, timezone
import hashlib
import json
from signalforge.demo import demo_records
from signalforge.exposure import sample_assets
from signalforge.evidence import case_id, evidence_packet, packet_markdown, packet_json
from signalforge.detection import hypotheses, playbook


def test_reproducible_case_ids_and_valid_sha256_manifest():
    record = demo_records()[1]
    data = evidence_packet(record, sample_assets(), now=datetime(2026,10,26,tzinfo=timezone.utc))
    assert data["case_id"] == case_id(record)
    assert data["classification"] == "SYNTHETIC TRAINING"
    digest = data.pop("sha256_data")
    assert hashlib.sha256(json.dumps(data,sort_keys=True,ensure_ascii=False,separators=(",", ":")).encode()).hexdigest() == digest
    data["sha256_data"] = digest
    assert packet_json(data).startswith("{")
    assert "operator-declared" in packet_markdown(data)


def test_hypotheses_are_labeled_as_unverified():
    record = demo_records()[0]
    hypotheses_found = hypotheses(record)
    assert any("T1486" in h.technique for h in hypotheses_found)
    assert "not observed adversary behavior" in playbook(record)
