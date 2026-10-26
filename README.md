# SignalForge 720

A local SOC practice lab by [@aounali720](https://github.com/aounali720). Built with Python, Streamlit and SQLite.

SignalForge collects CISA KEV entries and security news, keeps investigation notes, and exports case reports. You can also load four fictional cases and three lab assets to try it without network access or API keys.

I use this project to practice what comes after reading an advisory: deciding what needs attention, checking an inventory, choosing useful logs, and writing down the findings. The `720` name comes from my GitHub handle.

This is a single-user learning project. Inventory matches are based on CVEs you enter; they do not verify vulnerable versions. Detection worksheets suggest things to investigate. The app does not scan hosts or confirm an incident.

## Run locally

Use **Python 3.12**. The lock files and CI use that version.

On Windows, open PowerShell **inside the project folder**:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.lock
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Keep PowerShell open, then visit `http://127.0.0.1:8501`. To stop the app, press `Ctrl+C`.

On Linux or macOS:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock
python -m streamlit run app.py
```

If your browser says “connection refused,” check the terminal first. Wait for Streamlit to print its address and use the port it shows. If it exited with an error, fix that error before opening the page again. On Windows, use an approved Python installation if App Control blocks an extension; keep system security controls enabled.

Docker is also supported:

```bash
docker compose up --build
```

Compose binds to `127.0.0.1:8501`. The app has no login system; keep it local or use an authenticated proxy with HTTPS.

## Try the lab

1. Click **Load 720 signature lab** in the sidebar. All four cases and three assets are fictional.
2. In **Analyst Queue**, set the dataset to **Demo**, open the VPN case, and save an investigation note.
3. In **Exposure Lab**, inspect the assets with `CVE-2099-0001` and `CVE-2099-0002`. Both CVEs are invented for the exercise.
4. In **Detection Lab**, select a case, review its suggested logs, and download the worksheet.
5. In **Evidence Binder**, export the case as Markdown or JSON. It includes your note, inventory matches and ISO/NIST evidence prompts.
6. In **Content Studio**, enable training scenarios to try the free post template and card generator.

The [demo walkthrough](docs/demo-walkthrough.md) covers these steps in more detail. There is also a [sample inventory](assets/example-inventory.csv) and a [sample case report](docs/example-synthetic-case.md).

## What is in the dashboard

| Tab | Use it to |
| --- | --- |
| Signal Board | See public records by priority and publisher |
| Analyst Queue | Search cases, change their status and save notes |
| Exposure Lab | Import asset CSVs and match the CVEs you declared |
| Detection Lab | Review keyword-based ATT&CK hypotheses and telemetry questions |
| Evidence Binder | Export case notes, inventory matches and control references |
| Daily Brief | Summarize records published within a selected date window |
| Content Studio | Prepare post drafts and graphics for review |
| Methodology | Check how scores and references should be interpreted |

**Sync live sources** fetches the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), optional [FIRST EPSS](https://www.first.org/epss/) data, and RSS excerpts from BleepingComputer, The Hacker News and Help Net Security. It runs when you request it. Sources can fail independently; the app reports those failures and keeps records from the others. Read the linked advisories before acting on them.

Notes and imported assets are stored in `data/signalforge.sqlite`. Set `SF720_DB_PATH` to use another location. Inventory uploads are limited to 500 assets and 1 MB. Use fictional inventories for public demos and keep private notes, databases and exports out of Git.

## Command line

On Windows, use the virtual environment's Python:

```powershell
.\.venv\Scripts\python.exe -m signalforge.cli demo
.\.venv\Scripts\python.exe -m signalforge.cli stats
.\.venv\Scripts\python.exe -m signalforge.cli case --key demo:2 --output reports/lab-case.md
.\.venv\Scripts\python.exe -m signalforge.cli case --key demo:2 --format json --output reports/lab-case.json
.\.venv\Scripts\python.exe -m signalforge.cli sync --days 45
.\.venv\Scripts\python.exe -m signalforge.cli brief --brief-days 3 --output reports/public-brief.md
```

With an activated environment on Linux or macOS, use `python -m signalforge.cli` for the same commands. Briefs exclude synthetic cases, unknown publication dates and future-dated records.

## Optional writing and artwork APIs

The offline post template and card generator are free to use without credentials. For OpenAI or Claude drafts, copy `.env.example` to `.env` and fill in the relevant `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`. OpenAI concept artwork also uses `OPENAI_API_KEY`. Model names can be changed in `.env`.

Writing calls send the selected titles and excerpts to the provider. Artwork calls send the headline you entered. Keep private information out of those inputs. Paid API calls may incur charges, and all drafts need review. AI-generated artwork is labeled. The app does not publish posts automatically.

## Scores and evidence

The advisory score adds 70 for KEV membership, 12 for reported ransomware use, and an EPSS boost of `round(18 × sqrt(p))`. Non-KEV records can also receive up to 24 for the strongest matching keyword and 6 for mentioning a CVE. Scores are capped at 100: High starts at 65, Medium at 25.

The asset review score is `round(0.65 × advisory score) + 15 if internet-exposed + 5/12/20 for low/medium/high declared criticality`, capped at 100. These scores help order a review; they are not CVSS or a business risk assessment.

Case reports use stable `SF720-XXXXXXXX` identifiers and include a SHA-256 digest of the canonical JSON. Keep a trusted copy of the digest if you want to check later changes. It is not a digital signature. ISO 27001 and NIST CSF references are evidence prompts, not compliance findings.

## Development

```bash
python -m pip install -r requirements-dev.lock
python -m pytest -q
python -m ruff check --select E9,F63,F7,F82 .
python -m pip check
```

The 36 tests run offline, including dashboard interactions against temporary databases. Live feeds and paid APIs need separate checks in your environment. [Review notes](docs/review-notes.md) record the earlier bug fixes and validation limits.

The range files (`requirements.txt`, `requirements-dev.txt`) describe allowed dependencies. The two `.lock` files pin the Python 3.12 environment used by Docker and CI. Resolve updates in a clean environment, review both locks, and rerun the checks above. Exact pins are not artifact hashes.

To audit runtime dependencies, install `pip-audit==2.10.0` in a separate tooling environment and run `python -m pip_audit -r requirements.lock`.

[CI](.github/workflows/ci.yml) runs tests, fatal-error lint checks and the dependency audit. The [public-brief workflow](.github/workflows/daily-brief.yml) runs on a schedule or manually and keeps the brief as a seven-day artifact. It requires no paid API keys and does not commit reports or post to social media.

## Project layout

- `app.py` — Streamlit dashboard
- `signalforge/` — collectors, scoring, persistence, inventory matching, worksheets and exports
- `assets/` — sample inventory and graphics
- `docs/` — design notes, demo steps and portfolio material
- `tests/` — offline tests
- `reports/demo-case.*` — tracked fictional examples; other generated reports are ignored

![Data flow](assets/architecture.svg)

See [architecture notes](docs/architecture.md), [portfolio notes](docs/portfolio-kit.md) and [security guidance](SECURITY.md).

MIT License. This is an independent project with no endorsement from CISA, FIRST, MITRE, ISO, NIST or the publishers whose feeds it uses. Follow source terms and keep the fictional lab data labeled when sharing it.
