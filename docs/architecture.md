# SignalForge 720 — system design notes

## Data flow and trust boundaries

1. **External, untrusted input:** CISA KEV JSON and RSS publisher excerpts are fetched with timeouts, parsed without executing embedded content, and stored with their source URL. EPSS is an optional third-party estimate, not a severity score.
2. **Public fact vs local claim:** KEV membership indicates known exploitation in the wild. Neither KEV nor a media headline proves that a particular **asset** was affected.
3. **Explainable triage:** base score uses catalog membership, ransomware indicator, EPSS and limited keyword signals. All scores are labeled heuristics, not CVSS.
4. **Operator-declared inventory:** CSV loading is restricted to small files and exact CVE strings. The local matching table intersects explicit CVE IDs only. It does not fingerprint, scan, exploit, or infer version impact.
5. **Hypothesis layer:** ATT&CK mappings and telemetry recommendations are generated from keyword templates. They require manual threat-model validation, lab telemetry, false-positive review, and lawful authority to test.
6. **Evidence packet:** cases combine source links, analyst notes, inventory intersections, control-evidence suggestions, and detection ideas. A deterministic case ID derives from the source key. A SHA-256 digest allows comparing exported canonical JSON **if the expected digest is retained separately**. It does not authenticate who wrote the packet.
7. **Publication boundary:** Source-backed Markdown summaries and optional LLM LinkedIn drafts are review-only. AI is never allowed to automatically post; API credentials are environment variables.

## Scoring, status, and persistence

- Base score: KEV +70, ransomware +12, EPSS boost `round(18 × sqrt(p))`; for non-KEV only, strongest metadata keyword +0–24 and CVE mention +6.
- Priority: High ≥65; Medium 25–64; Low <25.
- Declared asset review score: 65% base score plus exposure and criticality indicators; **review order**, not validated risk.
- SQLite `threats` table keeps case statuses/notes across source upserts; separate `assets` table stores inventory declarations. No immutable event log or RBAC is implemented.

## Compliance reference scope

The case packet suggests **ISO/IEC 27001:2022 Annex A 8.8** (technical vulnerability management), **A 8.16** (monitoring activities), and **NIST CSF 2.0 functions** as evidence collection prompts. The package is not a control assessment and does not audit an organization.

## Known limitations and extensions

No CVSS feed, business criticality validation, authenticated vulnerability scan, affected-version mapping, patch verification, proprietary threat-intel subscriptions, SIEM integration, Sigma rule validation, ATT&CK technique detection, team identity/roles or production-ready audit trail. Next practical extension: correlate a detection workbook with *synthetic Wazuh/Sysmon/Snort alerts*, then explicitly document true/false positives and test coverage.
