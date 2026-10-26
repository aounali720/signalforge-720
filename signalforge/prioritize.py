"""Transparent triage heuristic, NOT CVSS, exploit proof or production risk model."""
from __future__ import annotations
import math
import re
from .models import ThreatRecord

KEYWORDS = {
    "ransomware": 24,
    "zero-day": 24,
    "0-day": 24,
    "actively exploited": 22,
    "remote code execution": 20,
    "authentication bypass": 18,
    "data breach": 18,
    "supply chain": 15,
    "phishing": 12,
    "malware": 12,
    "vulnerability": 9,
}


def score(record: ThreatRecord) -> ThreatRecord:
    points = 0
    reasons: list[str] = []
    if record.kev:
        points += 70
        reasons.append("Simulated KEV catalog flag for training (+70)" if record.is_demo else "In CISA Known Exploited Vulnerabilities catalog (+70)")
    if record.ransomware:
        points += 12
        reasons.append("Simulated ransomware use for training (+12)" if record.is_demo else "CISA reports known ransomware campaign use (+12)")
    if record.epss is not None:
        # EPSS is a probability between 0 and 1; this maps it to a heuristic boost.
        boost = round(18 * math.sqrt(max(0.0, min(1.0, record.epss))))
        points += boost
        reasons.append(f"FIRST EPSS probability {record.epss:.3f} (+{boost})")
    if not record.kev:
        content = f"{record.title} {record.summary}".lower()
        matched = [(phrase, weight) for phrase, weight in KEYWORDS.items() if re.search(r"\b" + re.escape(phrase) + r"\b", content)]
        if matched:
            phrase, weight = max(matched, key=lambda x: x[1])
            points += weight
            reasons.append(f"Headline/excerpt keyword: {phrase} (+{weight}; unverified)")
        if record.cve:
            points += 6
            reasons.append("Mentions a CVE (+6; not proof of exploitation)")
    record.priority_score = min(100, points)
    record.priority = "High" if points >= 65 else "Medium" if points >= 25 else "Low"
    record.rationale = "; ".join(reasons) or "No priority signals in the available metadata"
    return record
