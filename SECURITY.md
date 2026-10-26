# Security notes

SignalForge 720 is a single-user practice app. Run it locally, or put it behind authentication and HTTPS. Docker Compose binds to loopback by default. A public deployment also needs network restrictions and resource limits; the app has no built-in authentication.

Use GitHub's private vulnerability reporting for this repository when available. Keep credentials and private case details out of public issues.

## Credentials and external services

- Keep `.env`, API keys, and screenshots containing credentials out of Git. Copy `.env.example` only when configuring an optional provider, and leave tracked example keys blank. Future credentialed automation should use GitHub encrypted secrets.
- Offline demos and template drafts require no credentials. Optional AI requests may incur charges and always need review before use.
- Writing providers receive selected source metadata, including titles and excerpts. The artwork provider receives the entered headline. The app does not fetch the linked articles for the model. Do not include secrets or private incident details in these inputs.
- Provider errors shown in the UI omit response text because it could echo request material. The application does not store API keys in SQLite.
- Treat feeds and excerpts as untrusted input. Model instructions reduce prompt-injection risk but do not guarantee reliable output. Honor feed terms and rate limits.

## Inventories and exports

Use fictional inventories in a public demo. Uploading an inventory does not send it to an AI provider, but SQLite files and exported cases can still contain sensitive asset details or analyst notes. Protect those local copies.

CVE matching checks only the IDs declared in the inventory. It does not scan a host or verify an affected version. `CVE-2099-*` identifiers and their KEV/ransomware flags are fictional training data. Keep those labels when sharing screenshots or exports.

ATT&CK worksheets suggest questions and lab exercises; they are not validated detection rules. ISO/NIST references suggest evidence to collect, not an audit result. Priority scores are review heuristics, not CVSS or business-impact ratings.

The JSON export's unkeyed SHA-256 digest supports comparison with a separately retained value. It is not a signature. CSV exports escape formula-like values from feeds to reduce spreadsheet formula-injection risk.

## Maintenance

Dependency locks target Python 3.12. Update them together and run the CI vulnerability audit. If a finding is accepted, document why it applies or does not apply and what mitigation is in place.

Secret-pattern scans can miss credentials and other sensitive content. If a credential reaches Git, revoke it first. Deleting the file or adding an ignore rule does not remove earlier copies from history.

RSS entries with unknown dates and future-dated records are excluded from dated briefs. Check original publication dates and sources before sharing a report.
