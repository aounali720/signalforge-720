"""Ingestion of official CISA KEV JSON, FIRST EPSS, and short RSS metadata.

The application does not scrape full copyrighted articles, follow arbitrary URLs,
execute feed content, or mark article claims as confirmed exploitation.
"""
from __future__ import annotations
from datetime import date, datetime, timedelta, timezone
from hashlib import sha256
import re
from urllib.parse import urlparse, urlunparse
import requests
from xml.etree import ElementTree as ET
from email.utils import parsedate_to_datetime
from .models import ThreatRecord
from .prioritize import score

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
RSS_FEEDS = {
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "The Hacker News": "https://thehackernews.com/feeds/posts/default?alt=rss",
    "Help Net Security": "https://www.helpnetsecurity.com/feed/",
}
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")
HEADERS = {"User-Agent": "SignalForgeSOC/1.0 (+portfolio; contact in GitHub README)", "Accept": "application/json, application/rss+xml, application/xml, */*"}


def clean_text(value: str, max_len: int = 1400) -> str:
    import html
    return re.sub(r"\s+", " ", html.unescape(TAG_RE.sub(" ", value or ""))).strip()[:max_len]


def safe_url(value: str) -> str:
    """Only allow HTTP(S) URLs; canonicalize by removing tracking fragments."""
    parsed = urlparse((value or "").strip())
    if parsed.scheme not in ("https", "http") or not parsed.netloc or parsed.username or parsed.password:
        return ""
    return urlunparse((parsed.scheme, parsed.netloc.lower(), parsed.path, "", parsed.query, ""))


def parse_kev(payload: dict, days: int = 45, today: date | None = None) -> list[ThreatRecord]:
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise ValueError("CISA response is missing the vulnerabilities list")
    cutoff = (today or date.today()) - timedelta(days=days)
    found = []
    for raw in payload["vulnerabilities"]:
        if not isinstance(raw, dict):
            continue
        cve = str(raw.get("cveID", "")).upper().strip()
        published = str(raw.get("dateAdded", ""))
        if not CVE_RE.fullmatch(cve):
            continue
        try:
            if date.fromisoformat(published) < cutoff:
                continue
        except ValueError:
            continue
        ransomware = str(raw.get("knownRansomwareCampaignUse", "")).lower() == "known"
        record = ThreatRecord(
            key=f"cisa:{cve}",
            title=clean_text(str(raw.get("vulnerabilityName") or cve), 220),
            source="CISA KEV",
            url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve={cve}",
            published_at=published,
            summary=clean_text(f"{raw.get('shortDescription', '')} Required action: {raw.get('requiredAction', '')}", 1200),
            cve=cve, kev=True, ransomware=ransomware,
        )
        found.append(score(record))
    return sorted(found, key=lambda r: r.published_at, reverse=True)


def parse_rss(payload: bytes | str, source: str, limit: int = 30) -> list[ThreatRecord]:
    """Parse RSS 2.0 or Atom using the Python standard library."""
    if len(payload) > 3_000_000:
        raise ValueError("RSS feed exceeds 3 MB safety limit")
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise ValueError(f"Malformed RSS / Atom feed from {source}") from exc
    entries = root.findall(".//item")
    atom = not entries
    if atom:
        entries = root.findall(".//{http://www.w3.org/2005/Atom}entry")
    if not entries:
        raise ValueError(f"No RSS or Atom entries from {source}")

    def field(entry, name: str) -> str:
        if atom:
            el = entry.find(f"{{http://www.w3.org/2005/Atom}}{name}")
        else:
            el = entry.find(name)
        return "" if el is None else "".join(el.itertext()).strip()

    records = []
    for entry in entries[:limit]:
        title = clean_text(field(entry, "title"), 220)
        url = ""
        if atom:
            for link in entry.findall("{http://www.w3.org/2005/Atom}link"):
                if link.attrib.get("rel", "alternate") == "alternate":
                    url = safe_url(link.attrib.get("href", ""))
                    if url:
                        break
        else:
            url = safe_url(field(entry, "link"))
        if not title or not url:
            continue
        abstract = clean_text(field(entry, "summary") or field(entry, "description") or field(entry, "content"), 900)
        match = CVE_RE.search(title + " " + abstract)
        timestamp = field(entry, "published") or field(entry, "updated") or field(entry, "pubDate")
        try:
            if atom:
                published = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
            else:
                published = parsedate_to_datetime(timestamp).astimezone(timezone.utc).isoformat()
        except (ValueError, TypeError, OverflowError):
            published = datetime.now(timezone.utc).isoformat()
        records.append(score(ThreatRecord(
            key="rss:" + sha256(url.encode("utf-8")).hexdigest()[:24],
            title=title, source=source, url=url, published_at=published,
            summary=abstract, cve=match.group(0).upper() if match else "",
        )))
    return records


def fetch_kev(session: requests.Session, days: int = 45) -> list[ThreatRecord]:
    try:
        response = session.get(KEV_URL, headers=HEADERS, timeout=25)
        response.raise_for_status()
        return parse_kev(response.json(), days=days)
    except (requests.RequestException, ValueError):
        # Official CISA GitHub mirror is updated shortly after the canonical feed.
        response = session.get(KEV_MIRROR, headers=HEADERS, timeout=25)
        response.raise_for_status()
        return parse_kev(response.json(), days=days)


def fetch_rss(session: requests.Session, source: str, url: str, limit: int = 30) -> list[ThreatRecord]:
    if source not in RSS_FEEDS or RSS_FEEDS[source] != url:
        raise ValueError("Unsupported feed: only predefined sources are allowed")
    response = session.get(url, headers=HEADERS, timeout=25)
    response.raise_for_status()
    return parse_rss(response.content, source, limit)


def enrich_epss(session: requests.Session, records: list[ThreatRecord]) -> list[ThreatRecord]:
    """Optional EPSS enrichment. Never confuse EPSS likelihood with severity."""
    cves = list(dict.fromkeys(record.cve for record in records if record.cve))
    scores: dict[str, float] = {}
    batch = []
    for cve in cves + [None]:
        if cve is not None and len(",".join(batch + [cve])) <= 1800:
            batch.append(cve)
            continue
        if batch:
            response = session.get(EPSS_URL, headers=HEADERS, params={"cve": ",".join(batch)}, timeout=25)
            response.raise_for_status()
            for item in response.json().get("data", []):
                try:
                    value = float(item["epss"])
                    if 0 <= value <= 1:
                        scores[str(item["cve"]).upper()] = value
                except (KeyError, TypeError, ValueError):
                    continue
        batch = [cve] if cve is not None else []
    for record in records:
        record.epss = scores.get(record.cve)
        score(record)
    return records


def collect(days: int = 45, use_kev: bool = True, use_rss: bool = True, use_epss: bool = True, session: requests.Session | None = None) -> tuple[list[ThreatRecord], list[str]]:
    """Independent failures: return good sources and a visible list of errors."""
    sess = session or requests.Session()
    records: list[ThreatRecord] = []
    errors: list[str] = []
    if use_kev:
        try:
            records.extend(fetch_kev(sess, days))
        except (requests.RequestException, ValueError, KeyError) as exc:
            errors.append(f"CISA KEV: {type(exc).__name__}: {exc}")
    if use_rss:
        for name, url in RSS_FEEDS.items():
            try:
                records.extend(fetch_rss(sess, name, url))
            except (requests.RequestException, ValueError) as exc:
                errors.append(f"{name}: {type(exc).__name__}: {exc}")
    if use_epss and records:
        try:
            enrich_epss(sess, records)
        except (requests.RequestException, ValueError, KeyError) as exc:
            errors.append(f"FIRST EPSS: {type(exc).__name__}: {exc}")
    return list({record.key: record for record in records}.values()), errors
