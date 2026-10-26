"""Clearly synthetic examples for safe offline demonstrations.

Never present these fictional scenarios as breaking news or confirmed CVEs.
"""
from datetime import date, timedelta
from .models import ThreatRecord
from .prioritize import score


def demo_records() -> list[ThreatRecord]:
    today = date.today()
    examples = [
        ("demo:1", "[DEMO] Simulated ransomware alert for a fictional retailer", "Training Scenario", "An exercise scenario describing suspicious file-encryption behavior. No real organization was affected.", False, False, ""),
        ("demo:2", "[DEMO] Fictional VPN appliance authentication bypass", "Training Scenario", "Simulated analyst exercise: assess exposure, review logs and plan mitigations.", True, True, "CVE-2099-0001"),
        ("demo:3", "[DEMO] Phishing campaign in a simulated finance team", "Training Scenario", "Exercise evidence includes email headers, URL indicators and a user-reported suspicious message.", False, False, ""),
        ("demo:4", "[DEMO] Supply chain advisory for an imaginary package", "Training Scenario", "Exercise record about validating library versions and reviewing application deployments.", False, False, "CVE-2099-0002"),
    ]
    output = []
    for index, (key, title, src, summary, kev, ransomware, cve) in enumerate(examples):
        output.append(score(ThreatRecord(
            key=key, title=title, source=src, summary=summary,
            published_at=str(today - timedelta(days=index)),
            url="https://example.com/training-scenario", cve=cve,
            kev=kev, ransomware=ransomware, is_demo=True,
        )))
    return output
