# Five-minute demo

**00:00 — Introduce the app.** SignalForge 720 is a local SOC practice lab. It helps organize public advisories and case notes. It does not scan networks or confirm that an asset was exploited.

**00:40 — Load the lab.** Click **Load 720 signature lab** to add four fictional cases and three lab assets. On the Signal Board, check the training-record count.

**01:30 — Save a triage note.** Open Analyst Queue, set Dataset to Demo, and select the fictional VPN case. Record what you would check next. Explain the difference between a source's claim, an EPSS estimate, and evidence from an affected system.

**02:15 — Check the inventory match.** In Exposure Lab, show the exact match for a fictional `CVE-2099-*` identifier. The match comes from the declared CSV data; it does not verify a product version or vulnerability.

**03:10 — Work through a detection idea.** Open Detection Lab, review the suggested ATT&CK technique and telemetry, then export the worksheet. Describe how you would test the idea with benign lab events and check false positives. These worksheets are not validated Sigma rules.

**04:10 — Export the case.** Select the same case in Evidence Binder and download Markdown and JSON. Show where the notes and control-evidence prompts appear. Explain how to compare the canonical JSON's SHA-256 digest with a separately retained value. The digest does not identify the author or establish auditor approval.

**04:45 — Show the output.** In Content Studio, enable Show synthetic scenarios in Content Studio, make a post card, and review the draft before export. Keep the training label visible. Close with one extension you would test next, such as Wazuh telemetry, affected-version mapping, or detection validation. These are proposed extensions, not current capabilities.
