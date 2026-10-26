# Portfolio review changes

## Bugs fixed

- Literal SQLite search now escapes backslashes before LIKE wildcards, so searches containing `\`, `%`, or `_` return the intended records.
- Inventory CSV parsing accepts whitespace between semicolon-separated CVEs and rejects ambiguous duplicate column headers.
- Malformed URLs (IPv6 brackets, invalid ports, whitespace, backslashes) are rejected without crashing feed parsing. Source links in the queue use validated link buttons.
- Missing or malformed RSS dates remain unknown instead of being rewritten to the current time. Dated briefs exclude unknown and future publication dates.
- Saving triage and importing inventories refresh the dashboard immediately, including its queue, metrics, and evidence binder.
- Drafts and graphics are invalidated when their source selection or generation inputs change, preventing stale content from appearing to describe a different selection.
- Provider error details are withheld from the UI, preventing accidental disclosure through provider responses. Expected provider/network/decoding errors remain actionable without displaying credentials.

## Dashboard and preserved functionality

The AOUNSEC / 720 hero, colors, generated visual identity, and all eight modules remain.
Added a concise empty-state walkthrough, public/training record counts, a clarified stored-record
metric, provider data-sharing guidance, and current Streamlit stretch-width APIs.
SOC triage, KEV/RSS/EPSS intake, inventory intersections, ATT&CK-inspired workbooks,
ISO/NIST evidence guidance, integrity hashes, briefs, templates, and optional paid providers remain available.

## Repository and supply-chain safety

Restored `.gitignore`, `.env.example`, `.dockerignore`, offline CI, and the scheduled/manual
public briefing workflow. Local secrets, databases, inventories and generated reports are
excluded from commits/build contexts. CI actions are pinned and repository permissions are
read-only; the brief is an artifact, never an automatic commit or social post.
Runtime/development locks target Python 3.12 and are used by Docker and CI. Streamlit's
minimum was raised for current layout APIs. Pillow was upgraded to 13.0.0 to resolve the
37 advisories reported against 12.3.0 by the runtime dependency audit.
README and security guidance document installation, updating, data boundaries and limitations.

## Verification

The original suite passed all 23 tests before changes. Regression and interaction coverage
now includes literal search, CSV ambiguity/normalization, malformed URLs, feed freshness,
detection worksheets, demo loading, journal persistence, draft lifecycle, and provider error redaction.
All 36 tests pass on Python 3.12. Fatal-error Ruff checks and `pip check` pass.
Runtime `pip-audit` reports no known vulnerabilities after the Pillow upgrade.
A pattern scan of current files and 40 historical Git blobs found no API-token/private-key matches;
this is a heuristic, not proof that every possible secret is absent.

Live publisher feeds and paid provider calls are not exercised by the offline suite.
GitHub-hosted CI must run after push; local checks do not establish its outcome.

Docker Compose configuration validates. The image built using a temporary validation
Dockerfile that mounts this cloud's trusted CA bundle only for pip, plus the existing proxy
and resolved proxy hostname. The tracked Dockerfile is not coupled to those cloud settings;
ordinary build attempts in this machine failed on builder DNS and then proxy CA trust.
TLS verification was preserved. The resulting container passed non-root-user and build-context
checks (no `.env` or `.git`), HTTP health/HTML checks, and CLI demo/stats/JSON case export.
The disposable validation container was removed afterward.
