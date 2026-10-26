"""SQLite persistence for ingestion, triage, and audit-friendly timestamps."""
from __future__ import annotations
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import os
import sqlite3
from .models import ThreatRecord

STATUSES = ("New", "Investigating", "Actioned", "Not Applicable")


def db_path() -> Path:
    return Path(os.getenv("SF720_DB_PATH", "data/signalforge.sqlite"))


@contextmanager
def connect(path: str | Path | None = None):
    target = Path(path) if path else db_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(path: str | Path | None = None) -> None:
    with connect(path) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS threats (
                key TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                source TEXT NOT NULL,
                url TEXT NOT NULL,
                published_at TEXT NOT NULL,
                summary TEXT NOT NULL,
                cve TEXT NOT NULL DEFAULT '',
                kev INTEGER NOT NULL DEFAULT 0,
                ransomware INTEGER NOT NULL DEFAULT 0,
                epss REAL,
                priority_score INTEGER NOT NULL DEFAULT 0,
                priority TEXT NOT NULL DEFAULT 'Low',
                rationale TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'New',
                analyst_notes TEXT NOT NULL DEFAULT '',
                is_demo INTEGER NOT NULL DEFAULT 0,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_priority ON threats(priority_score DESC);
            CREATE INDEX IF NOT EXISTS idx_date ON threats(published_at DESC);
        """)


def upsert(records: list[ThreatRecord], path: str | Path | None = None) -> int:
    if not records:
        return 0
    init_db(path)
    now = datetime.now(timezone.utc).isoformat()
    with connect(path) as db:
        db.executemany("""
            INSERT INTO threats (
                key, title, source, url, published_at, summary, cve, kev,
                ransomware, epss, priority_score, priority, rationale, is_demo,
                first_seen, last_seen
            ) VALUES (
                :key, :title, :source, :url, :published_at, :summary, :cve, :kev,
                :ransomware, :epss, :priority_score, :priority, :rationale, :is_demo,
                :first_seen, :last_seen
            )
            ON CONFLICT(key) DO UPDATE SET
                title=excluded.title, source=excluded.source, url=excluded.url,
                published_at=excluded.published_at, summary=excluded.summary,
                cve=excluded.cve, kev=excluded.kev,
                ransomware=excluded.ransomware, epss=excluded.epss,
                priority_score=excluded.priority_score, priority=excluded.priority,
                rationale=excluded.rationale, last_seen=excluded.last_seen
        """, [dict(r.to_dict(), kev=int(r.kev), ransomware=int(r.ransomware), is_demo=int(r.is_demo), first_seen=now, last_seen=now) for r in records])
    return len(records)


def list_threats(path: str | Path | None = None, *, search: str = "", priority: str = "All", source: str = "All", status: str = "All", demo: bool | None = None, limit: int = 2000) -> list[ThreatRecord]:
    init_db(path)
    clauses = []
    args: list = []
    if search:
        clauses.append("(title LIKE ? OR summary LIKE ? OR cve LIKE ?)")
        # Defensively escape LIKE meta characters so the input is literal.
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        clauses[-1] = clauses[-1].replace(" LIKE ?", " LIKE ? ESCAPE '\\'")
        args.extend([f"%{escaped}%"] * 3)
    if priority != "All":
        clauses.append("priority = ?")
        args.append(priority)
    if source != "All":
        clauses.append("source = ?")
        args.append(source)
    if status != "All":
        clauses.append("status = ?")
        args.append(status)
    if demo is not None:
        clauses.append("is_demo = ?")
        args.append(int(demo))
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    statement = ("SELECT * FROM threats" + where + " ORDER BY priority_score DESC, published_at DESC LIMIT ?")
    args.append(max(1, min(int(limit), 10000)))
    with connect(path) as db:
        rows = db.execute(statement, args).fetchall()
    return [ThreatRecord(**dict(row, kev=bool(row["kev"]), ransomware=bool(row["ransomware"]), is_demo=bool(row["is_demo"]))) for row in rows]


def save_triage(key: str, status: str, notes: str, path: str | Path | None = None) -> bool:
    if status not in STATUSES:
        raise ValueError("Unknown status")
    if len(notes) > 5000:
        raise ValueError("Notes are limited to 5000 characters")
    with connect(path) as db:
        cursor = db.execute("UPDATE threats SET status = ?, analyst_notes = ? WHERE key = ?", (status, notes, key))
        return cursor.rowcount == 1
