"""Domain types shared by collectors, scoring and the UI."""
from dataclasses import asdict, dataclass, field


@dataclass
class ThreatRecord:
    key: str
    title: str
    source: str
    url: str
    published_at: str  # UTC ISO 8601 or date-only, from the publisher
    summary: str
    cve: str = ""
    kev: bool = False
    ransomware: bool = False
    epss: float | None = None
    priority_score: int = 0
    priority: str = "Low"
    rationale: str = ""
    status: str = "New"
    analyst_notes: str = ""
    is_demo: bool = False
    first_seen: str = ""
    last_seen: str = ""

    def to_dict(self) -> dict:
        return asdict(self)
