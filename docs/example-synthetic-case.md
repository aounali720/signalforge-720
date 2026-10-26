# SF720-AD2E09BA · Analyst evidence packet

**Classification:** SYNTHETIC TRAINING
**Generated (UTC):** 2026-10-26T00:15:37.164907+00:00
**Title:** [DEMO] Fictional VPN appliance authentication bypass
**Publisher:** Training Scenario
**Primary URL:** https://example.com/training-scenario
**CVE:** CVE-2099-0001

## Triage
- Status: New
- Heuristic: High (82/100)
- Reasons: Simulated KEV catalog flag for training (+70); Simulated ransomware use for training (+12)
- Notes: None recorded

## Inventory intersections (operator-declared, NOT validated exposure)
- SF720-LAB-VPN · CVE-2099-0001 · Review score 88/100 · Inventory-declared CVE match; NOT confirmed affected version or compromise

## Detection hypotheses (not observed techniques)
- **T1190 – Exploit Public-Facing Application** — Telemetry: Reverse proxy/WAF and application authentication logs. Question: Is there suspicious unauthenticated traffic to an exposed service?

## Suggested control/evidence references
- **ISO/IEC 27001:2022 A.8.8** · Management of technical vulnerabilities: Verify applicability, patch/mitigation evidence, asset scope
- **ISO/IEC 27001:2022 A.8.16** · Monitoring activities: Document monitoring coverage, alerts and investigation outcomes
- **NIST CSF 2.0 — Identify / Protect / Detect / Respond** · High-level functions, not scored compliance: Link owner, inventory, mitigations, detection and incident decisions

## Investigation checklist
- [ ] Read original vendor/CISA advisory and record retrieval date
- [ ] Validate owned asset/product versions before claiming exposure
- [ ] Confirm vulnerability/remediation status with asset owner
- [ ] Assess useful telemetry and validate detection hypotheses
- [ ] Preserve relevant logs and document analysis limitations
- [ ] Request peer review before issuing any external statement

SHA-256 of canonical packet data (excluding hash field): `af02d5c9f1b2c93ebee814f7e53fffec9f9f3d940bcaf4ca76a3eb606b38cd50`

> No automated exploitation, vulnerability validation, compliance certification, or incident attribution performed.
