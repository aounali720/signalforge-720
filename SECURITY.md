# Security notes

This is an educational single-user dashboard, not a hardened multi-tenant SOC platform.

- Keep `.env` and API credentials out of Git and screenshots.
- Deploy only locally or behind authentication and HTTPS. The included Docker Compose binds to loopback deliberately.
- Do not expose the Streamlit UI publicly without an authentication proxy, network policy, and resource limits.
- Public feeds and excerpts are untrusted; never follow instructions embedded in them.
- External URLs are publisher evidence links, not content fetched into the LLM.
- AI text and imagery require human approval; optional API requests may incur charges.
- Limit update frequency and honor upstream rate limits and publisher terms.
- No credentials are required to use the offline demos or template content generator.
- The heuristic is NOT CVSS, business impact, or an authoritative risk rating.

Please report potential issues privately through the GitHub repository security advisory flow rather than posting a public exploit.

## Inventories and evidence exports

- Import only training asset inventories for a public portfolio demo; real enterprise assets can be sensitive. The uploader doesn't transmit uploaded inventory to third-party providers, but local database/export copies still require protection.
- Exact CVE string equality is **not** a vulnerability scan or verification of affected versions.
- Synthetic `CVE-2099-*` identifiers are fictional. Any KEV/ransomware flags attached to them are explicitly simulated.
- ATT&CK hypotheses are education prompts, not tested detection rules or confirmed TTPs.
- JSON evidence hashes are unkeyed SHA-256 digests, not cryptographic signing or compliant audit evidence.
- CSV outputs sanitize formula-like text from untrusted feeds to reduce spreadsheet formula-injection risk.

## Credential handling and dependency updates

- Copy `.env.example` to a local `.env` only when configuring optional providers. Keep key fields empty in tracked examples; use GitHub encrypted secrets for any future credentialed automation.
- Provider errors shown in the UI intentionally omit response text, which could echo sensitive request material. No API keys are stored in the SQLite database by the application.
- Optional writing calls send selected public-source titles and excerpts to the chosen provider; optional artwork sends the entered headline. Do not put private incident details or secrets into these inputs. Provider instructions mitigate prompt injection but cannot guarantee trustworthy output.
- Dependency locks target Python 3.12. Keep them updated and run the CI vulnerability audit; do not bypass a finding without documenting its applicability and mitigation.
- Secret-pattern scanning is a heuristic. A clean scan cannot establish absence of all sensitive information. If a credential was committed, revoke it first; deleting it or adding ignore rules does not remove it from Git history.
- Unknown RSS publication dates are retained as unknown and excluded from dated briefs. Future-dated records are also excluded from briefs.
