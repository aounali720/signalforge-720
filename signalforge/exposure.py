"""Asset declarations and evidence-limited CVE-to-inventory intersections.

No scanning, fingerprinting, or unverified product-name matching occurs here.
An intersection means a CSV operator *declared* a CVE for an asset, NOT
that exploitation or vulnerability of that asset is independently proven.
"""
from __future__ import annotations
from dataclasses import dataclass
import csv
import hashlib
from io import StringIO
from pathlib import Path
import re
import sqlite3
from .database import connect
from .models import ThreatRecord

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
CRITICALITIES = ("Low", "Medium", "High")
FIELDS = ("asset_id", "product", "environment", "internet_exposed", "criticality", "known_cves", "owner")


@dataclass(frozen=True)
class AssetRecord:
    asset_id: str
    product: str
    environment: str
    internet_exposed: bool
    criticality: str
    known_cves: str
    owner: str
    is_demo: bool = False

    def cves(self) -> tuple[str, ...]:
        return tuple(x.strip().upper() for x in self.known_cves.split(";") if x.strip())


def create_assets_table(path: str | Path | None = None) -> None:
    with connect(path) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS assets (
           asset_id TEXT PRIMARY KEY, product TEXT NOT NULL, environment TEXT NOT NULL,
           internet_exposed INTEGER NOT NULL, criticality TEXT NOT NULL,
           known_cves TEXT NOT NULL, owner TEXT NOT NULL, is_demo INTEGER NOT NULL DEFAULT 0
        )""")


def parse_csv(content: str, *, demo: bool = False) -> list[AssetRecord]:
    if len(content.encode("utf-8")) > 1_000_000:
        raise ValueError("Inventory CSV must not exceed 1 MB")
    reader = csv.DictReader(StringIO(content.lstrip("\ufeff")))
    if not reader.fieldnames or any(k not in reader.fieldnames for k in FIELDS):
        raise ValueError("CSV headers must include: " + ", ".join(FIELDS))
    result: list[AssetRecord] = []
    seen: set[str] = set()
    for line, row in enumerate(reader, 2):
        if line > 501:
            raise ValueError("Limit the upload to 500 assets")
        if None in row:
            raise ValueError(f"Unexpected extra column on line {line}")
        asset_id = (row["asset_id"] or "").strip()
        criticality = (row["criticality"] or "").strip().title()
        flag = (row["internet_exposed"] or "").strip().lower()
        cves = (row["known_cves"] or "").strip().upper()
        if not asset_id or len(asset_id) > 80 or asset_id in seen:
            raise ValueError(f"Invalid or duplicate asset_id on line {line}")
        if criticality not in CRITICALITIES:
            raise ValueError(f"Invalid criticality on line {line}; use Low, Medium, or High")
        if flag not in ("true", "false", "yes", "no", "1", "0"):
            raise ValueError(f"Invalid internet_exposed flag on line {line}")
        if any(not _CVE.fullmatch(cve) for cve in cves.split(";") if cve.strip()):
            raise ValueError(f"Invalid CVE syntax on line {line}")
        if any(len((row[field] or "")) > 180 for field in ("product", "environment", "owner")):
            raise ValueError(f"Oversized CSV field on line {line}")
        seen.add(asset_id)
        result.append(AssetRecord(asset_id, (row["product"] or "").strip(),
                      (row["environment"] or "").strip(), flag in ("true", "yes", "1"),
                      criticality, ";".join(c.strip() for c in cves.split(";") if c.strip()),
                      (row["owner"] or "").strip(), demo))
    return result


def save_assets(assets: list[AssetRecord], path: str | Path | None = None) -> int:
    create_assets_table(path)
    with connect(path) as db:
        db.executemany("""INSERT INTO assets
          (asset_id,product,environment,internet_exposed,criticality,known_cves,owner,is_demo)
          VALUES (?,?,?,?,?,?,?,?)
          ON CONFLICT(asset_id) DO UPDATE SET product=excluded.product,
          environment=excluded.environment,internet_exposed=excluded.internet_exposed,
          criticality=excluded.criticality,known_cves=excluded.known_cves,
          owner=excluded.owner,is_demo=excluded.is_demo""",
          [(a.asset_id,a.product,a.environment,int(a.internet_exposed),a.criticality,
            a.known_cves,a.owner,int(a.is_demo)) for a in assets])
    return len(assets)


def list_assets(path: str | Path | None = None) -> list[AssetRecord]:
    create_assets_table(path)
    with connect(path) as db:
        rows = db.execute("SELECT * FROM assets ORDER BY asset_id").fetchall()
    return [AssetRecord(r["asset_id"],r["product"],r["environment"],bool(r["internet_exposed"]),
                        r["criticality"],r["known_cves"],r["owner"],bool(r["is_demo"])) for r in rows]


def exposure_score(threat: ThreatRecord, asset: AssetRecord) -> int:
    """Illustrative review order, not exploitation risk or CVSS."""
    return min(100, round(threat.priority_score * .65) + (15 if asset.internet_exposed else 0)
               + {"Low": 5, "Medium": 12, "High": 20}[asset.criticality])


def find_matches(threats: list[ThreatRecord], assets: list[AssetRecord]) -> list[dict]:
    matches = []
    for threat in threats:
        if not threat.cve or not _CVE.fullmatch(threat.cve.strip()):
            continue
        for asset in assets:
            if threat.cve.upper() in asset.cves():
                matches.append({"case_id": "SF720-" + hashlib.sha256(threat.key.encode()).hexdigest()[:8].upper(),
                                "asset_id": asset.asset_id, "asset_product": asset.product,
                                "declared_cve": threat.cve.upper(), "headline": threat.title,
                                "priority": threat.priority, "review_score": exposure_score(threat, asset),
                                "internet_exposed": asset.internet_exposed, "criticality": asset.criticality,
                                "is_demo": threat.is_demo or asset.is_demo,
                                "source": threat.url,
                                "warning": "Inventory-declared CVE match; NOT confirmed affected version or compromise"})
    return sorted(matches, key=lambda m: m["review_score"], reverse=True)


def sample_assets() -> list[AssetRecord]:
    """Invented assets, including fictional CVEs. Never present as actual infrastructure."""
    return [
        AssetRecord("SF720-LAB-VPN", "Fictional VPN gateway", "Home lab", True, "High", "CVE-2099-0001", "SOC trainee", True),
        AssetRecord("SF720-LAB-APP", "Imaginary application package", "Isolated VM", False, "Medium", "CVE-2099-0002", "SOC trainee", True),
        AssetRecord("SF720-LAB-WIN", "Windows telemetry workstation", "Detection lab", False, "Low", "", "SOC trainee", True),
    ]
