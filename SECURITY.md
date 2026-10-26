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
