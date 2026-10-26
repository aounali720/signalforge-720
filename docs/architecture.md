# SignalForge 720 — design notes

## Data flow

1. **Collect sources.** CISA KEV JSON and publisher RSS excerpts are fetched with timeouts. Parsing treats them as untrusted input and does not execute embedded content. Records keep their source URLs. Optional FIRST EPSS enrichment adds an exploitation-probability estimate.
2. **Rank the queue.** Catalog membership, the ransomware flag, EPSS, and a small keyword list contribute to the priority score. The app shows the reasons for each score. This is a review-order heuristic, not CVSS. KEV membership describes exploitation in the wild; it does not establish impact on an owned asset.
3. **Compare the inventory.** CSV imports are limited to 500 assets and 1 MB. Matching uses the CVE IDs entered by the operator. The app does not scan hosts, infer affected versions, or verify those declarations.
4. **Suggest investigation questions.** Keyword templates select ATT&CK-inspired techniques, possible telemetry, and benign lab exercises. Analysts still need to check relevance, collect permitted telemetry, and test false positives.
5. **Export a case.** A case combines source links, triage notes, inventory matches, detection ideas, and control-evidence prompts. The case ID is derived from its source key. The JSON export includes a SHA-256 digest of the canonical packet data. Compare it with a separately retained digest to check for changes; it does not authenticate the author.
6. **Prepare a draft.** Markdown summaries and optional AI-assisted LinkedIn drafts are available for review and download. The app does not post them. Optional provider credentials come from environment variables.

## Scores and storage

- Base score: KEV +70, ransomware +12, EPSS boost `round(18 × sqrt(p))`. Non-KEV records can also receive the strongest matching keyword score (+0–24) and +6 for mentioning a CVE.
- Priority: High ≥65; Medium 25–64; Low <25.
- Asset review score: `round(0.65 × advisory score)`, plus 15 for declared internet exposure and 5/12/20 for Low/Medium/High criticality, capped at 100. It orders reviews; it does not measure verified risk.
- SQLite stores cases in `threats` and declarations in `assets`. Source refreshes preserve case status and notes. There is no immutable event log or role-based access control.

## ISO and NIST references

Case exports suggest evidence for ISO/IEC 27001:2022 Annex A 8.8 (technical vulnerability management), A 8.16 (monitoring activities), and the NIST CSF 2.0 functions. These references help frame evidence collection. They do not constitute a control assessment or organizational audit.

## Limits and possible next steps

The app has no CVSS feed, affected-version mapping, patch verification, authenticated vulnerability scanning, or proprietary intelligence feeds. It does not integrate with a SIEM, validate Sigma rules, or detect ATT&CK techniques from telemetry. It also lacks team roles and a production audit trail; declared asset criticality is not independently checked.

A useful next experiment would be to connect a worksheet to synthetic Wazuh, Sysmon, or Snort events, then record expected results, false positives, and test coverage. That integration is not implemented.
