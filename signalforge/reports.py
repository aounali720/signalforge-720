"""Source-linked briefs and offline post drafts."""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
from .models import ThreatRecord


def recent(records: list[ThreatRecord], days: int = 3, *, now: datetime | None = None) -> list[ThreatRecord]:
    """Published-window filter; a daily brief should not recycle old high-score items."""
    today = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).date()
    cutoff = today - timedelta(days=days)
    retained = []
    for item in records:
        try:
            published = datetime.fromisoformat(item.published_at.replace("Z", "+00:00")).date()
        except ValueError:
            continue
        if cutoff <= published <= today:
            retained.append(item)
    return retained


def pick(records: list[ThreatRecord], max_items: int = 7) -> list[ThreatRecord]:
    return sorted(records, key=lambda r: (r.priority_score, r.published_at), reverse=True)[:max_items]


def digest(records: list[ThreatRecord], max_items: int = 7) -> str:
    selected = pick(records, max_items)
    today = datetime.now(timezone.utc).strftime("%B %d, %Y")
    if not selected:
        return f"# SignalForge 720 Daily Brief — {today} (UTC)\n\nNo records match the current selection.\n"
    demo_note = "\n> **TRAINING DATA ONLY:** Includes fictional cases, not current threat advisories.\n" if any(r.is_demo for r in selected) else ""
    lines = [f"# SignalForge 720 Daily Brief — {today} (UTC)", demo_note,
             "This brief summarizes public advisories and publisher excerpts. Priority scores set a review order; they are **not CVSS**."
             " Check vendor guidance and asset versions before taking action.", ""]
    for index, r in enumerate(selected, 1):
        lines += [f"## {index}. {r.title}",
                  f"- **Publisher:** {r.source} | **Published:** {r.published_at} | **Priority:** {r.priority} ({r.priority_score}/100)",
                  f"- **CVE:** {r.cve or 'Not specified'} | **CISA KEV:** {'Simulated yes (TRAINING ONLY)' if r.kev and r.is_demo else 'Yes' if r.kev else 'No / not confirmed'} | **EPSS:** {f'{r.epss:.3f}' if r.epss is not None else 'Unavailable'}",
                  f"- **Source excerpt:** {r.summary or 'Not provided.'}",
                  f"- **Why selected:** {r.rationale}",
                  f"- **Analyst next step:** {'Check asset versions against the vendor advisory, then review patches, mitigations and relevant logs.' if r.kev else 'Read the original source and check whether it applies to your assets.'}",
                  f"- **Source:** {r.url}", ""]
    lines += ["---", "Prepared by SignalForge 720 from the sources above. Asset impact has not been verified."]
    return "\n".join(lines)


def linkedin_template(records: list[ThreatRecord], max_items: int = 3) -> str:
    selected = pick(records, max_items)
    if not selected:
        return "Select at least one source record."
    if any(r.is_demo for r in selected):
        prefix = "SOC training exercise — synthetic examples\n\n"
    else:
        prefix = "Security notes\n\n"
    lines = [prefix]
    for index, r in enumerate(selected, 1):
        summary = r.summary.split(". Required action:")[0].strip() or r.title
        lines.append(f"{index}. {r.title}\n{summary[:220]}{'…' if len(summary) > 220 else ''}\nPriority: {r.priority} (analyst heuristic).")
    next_step = ("For this exercise, list the assets you would check, the logs you would review, and the evidence needed before making a claim."
                 if any(r.is_demo for r in selected) else
                 "Before acting, check the vendor advisory and affected versions in your inventory. CISA KEV records known exploitation in the wild; a news headline alone does not confirm it.")
    lines += ["", next_step, "", "Sources:"]
    for r in selected:
        lines.append(r.url)
    return "\n".join(lines)
