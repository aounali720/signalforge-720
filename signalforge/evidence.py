"""Auditable-looking but not cryptographically signed case exports.
SHA-256 makes accidental modifications detectable if a trusted hash is kept separately.
It is NOT proof of when the case was created or that data was externally verified.
"""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import json
from .models import ThreatRecord
from .exposure import AssetRecord, find_matches
from .detection import hypotheses


CONTROL_GUIDANCE = [
    ("ISO/IEC 27001:2022 A.8.8", "Management of technical vulnerabilities", "Verify applicability, patch/mitigation evidence, asset scope"),
    ("ISO/IEC 27001:2022 A.8.16", "Monitoring activities", "Document monitoring coverage, alerts and investigation outcomes"),
    ("NIST CSF 2.0 — Identify / Protect / Detect / Respond", "High-level functions, not scored compliance", "Link owner, inventory, mitigations, detection and incident decisions"),
]


def case_id(record: ThreatRecord) -> str:
    return "SF720-" + hashlib.sha256(record.key.encode("utf-8")).hexdigest()[:8].upper()


def evidence_packet(record: ThreatRecord, assets: list[AssetRecord], *, now: datetime | None = None) -> dict:
    asset_matches = find_matches([record], assets)
    data = {
        "schema": "signalforge720.case.1",
        "case_id": case_id(record),
        "created_utc": (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat(),
        "classification": "SYNTHETIC TRAINING" if record.is_demo else "PUBLIC SOURCE / UNVERIFIED ASSET IMPACT",
        "source": {"title": record.title, "publisher": record.source, "url": record.url,
                   "published_at": record.published_at, "cve": record.cve,
                   "cisa_kev": record.kev, "cisa_kev_is_simulated": bool(record.is_demo and record.kev), "epss": record.epss},
        "triage": {"status": record.status, "analyst_notes": record.analyst_notes,
                   "heuristic_priority": record.priority, "priority_score": record.priority_score,
                   "rationale": record.rationale},
        "declared_inventory_intersections": asset_matches,
        "detection_hypotheses": [
            {"technique": h.technique, "telemetry": h.telemetry, "analyst_question": h.analyst_question}
            for h in hypotheses(record)
        ],
        "suggested_control_evidence": [
            {"reference": ref, "topic": topic, "evidence_needed": request}
            for ref, topic, request in CONTROL_GUIDANCE
        ],
        "analyst_checklist": [
            "Read original vendor/CISA advisory and record retrieval date",
            "Validate owned asset/product versions before claiming exposure",
            "Confirm vulnerability/remediation status with asset owner",
            "Assess useful telemetry and validate detection hypotheses",
            "Preserve relevant logs and document analysis limitations",
            "Request peer review before issuing any external statement",
        ],
        "disclaimer": "No automated exploitation, vulnerability validation, compliance certification, or incident attribution performed.",
    }
    serialized = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    data["sha256_data"] = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return data


def packet_markdown(packet: dict) -> str:
    source, triage = packet["source"], packet["triage"]
    lines = [f"# {packet['case_id']} · Analyst evidence packet", "",
             f"**Classification:** {packet['classification']}",
             f"**Generated (UTC):** {packet['created_utc']}",
             f"**Title:** {source['title']}", f"**Publisher:** {source['publisher']}",
             f"**Primary URL:** {source['url']}", f"**CVE:** {source['cve'] or 'Not stated'}", "",
             "## Triage", f"- Status: {triage['status']}",
             f"- Heuristic: {triage['heuristic_priority']} ({triage['priority_score']}/100)",
             f"- Reasons: {triage['rationale']}", f"- Notes: {triage['analyst_notes'] or 'None recorded'}", "",
             "## Inventory intersections (operator-declared, NOT validated exposure)"]
    for row in packet["declared_inventory_intersections"]:
        lines.append(f"- {row['asset_id']} · {row['declared_cve']} · Review score {row['review_score']}/100 · {row['warning']}")
    if not packet["declared_inventory_intersections"]:
        lines.append("- None declared. This does not establish that assets are unaffected.")
    lines += ["", "## Detection hypotheses (not observed techniques)"]
    for h in packet["detection_hypotheses"]:
        lines.append(f"- **{h['technique']}** — Telemetry: {h['telemetry']}. Question: {h['analyst_question']}")
    if not packet["detection_hypotheses"]:
        lines.append("- None automatically suggested; inspect the advisory manually.")
    lines += ["", "## Suggested control/evidence references"]
    for c in packet["suggested_control_evidence"]:
        lines.append(f"- **{c['reference']}** · {c['topic']}: {c['evidence_needed']}")
    lines += ["", "## Investigation checklist"]
    for item in packet["analyst_checklist"]:
        lines.append(f"- [ ] {item}")
    lines += ["", f"SHA-256 of canonical packet data (excluding hash field): `{packet['sha256_data']}`",
              "", f"> {packet['disclaimer']}"]
    return "\n".join(lines) + "\n"


def packet_json(packet: dict) -> str:
    return json.dumps(packet, indent=2, ensure_ascii=False) + "\n"
