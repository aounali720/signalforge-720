# SignalForge 720 · @aounali720 portfolio notes

**Repository:** [aounali720/signalforge-720](https://github.com/aounali720/signalforge-720)

**Short description:** A local SOC practice app for reviewing public advisories, keeping case notes, and testing investigation ideas with fictional lab data.

**Topics:** `cybersecurity`, `soc-analyst`, `python`, `threat-intelligence`, `cisa-kev`, `epss`, `detection-engineering`, `grc`, `streamlit`

## CV entry

Use this after running the project yourself. Adjust the wording to match the work you can explain and demonstrate.

**SignalForge 720 — SOC practice lab** | Python, Streamlit, SQLite, CISA KEV, FIRST EPSS, MITRE ATT&CK concepts

- Built a Streamlit dashboard that imports public advisories and EPSS data, ranks records for review, and saves case notes in SQLite.
- Added CSV asset declarations, exact CVE matching, and detection worksheets with telemetry questions and benign lab exercises.
- Added Markdown and JSON case exports with source links, SHA-256 checksums, and ISO 27001/NIST CSF evidence prompts. Covered the offline workflow with automated tests.

The project also supports optional AI drafting, which requires review before use. Keep claims about production deployments, real investigations, detection accuracy, or audit results separate from what this lab demonstrates.

## Short project write-up

I built SignalForge 720 to practice the work that comes after seeing a security advisory. It's a Python/Streamlit app with a local SQLite database.

The app puts CISA KEV entries, EPSS data and security news in one queue. From there, an analyst can save triage notes, compare CVE IDs with a declared lab inventory, work through a detection hypothesis, and export the case as Markdown or JSON.

The offline demo has four fictional cases and three lab assets. That makes it possible to walk through the app without API keys or live feeds. Demo records stay labeled throughout the workflow.

The Content Studio includes a free post template, headline-based graphics, and optional AI drafting. Nothing is posted automatically.

Stack: Python, Streamlit, SQLite, REST/JSON, pytest, GitHub Actions

GitHub: https://github.com/aounali720/signalforge-720


## Screenshots and demo material

Capture the app while it is running: the Signal Board, Exposure Lab, a Detection Lab worksheet, and an Evidence Binder export. Leave the synthetic-data labels visible. A short recording of a note surviving a source refresh is useful evidence of persistence.

The cover in `assets/portfolio-cover.png` is an illustration. Use actual app captures when showing the interface.
