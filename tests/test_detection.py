from signalforge.demo import demo_records
from signalforge.detection import hypotheses, playbook


def test_detection_keeps_telemetry_and_training_boundaries():
    record = demo_records()[0]
    found = hypotheses(record)
    assert any('T1486' in h.technique and 'EDR' in h.telemetry for h in found)
    worksheet = playbook(record)
    assert 'Synthetic scenario: YES' in worksheet
    assert 'not observed adversary behavior' in worksheet
    assert 'Record expected and observed results' in worksheet
