"""Repeatable local analysis and export commands for the 720 lab."""
from __future__ import annotations
import argparse
from pathlib import Path
from dotenv import load_dotenv
from .database import list_threats, upsert
from .demo import demo_records
from .exposure import sample_assets, save_assets, list_assets
from .evidence import evidence_packet, packet_markdown, packet_json
from .reports import digest, recent
from .sources import collect


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(description="SignalForge 720: threat-to-evidence lab CLI")
    parser.add_argument("command", choices=["sync", "demo", "brief", "stats", "case"])
    parser.add_argument("--days", type=int, default=45)
    parser.add_argument("--brief-days", type=int, default=3)
    parser.add_argument("--key", default="", help="Local case's source key for a case export")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--output", default="")
    args = parser.parse_args()
    if args.command == "demo":
        print(f"Added {upsert(demo_records())} clearly synthetic training cases and {save_assets(sample_assets())} fictional lab assets.")
    elif args.command == "sync":
        records, errors = collect(days=args.days)
        print(f"Imported/refreshed: {upsert(records)}")
        for error in errors:
            print(f"SOURCE WARNING: {error}")
        if errors and not records:
            raise SystemExit(1)
    elif args.command == "stats":
        records = list_threats()
        print(f"Cases: {len(records)}; Live: {sum(not r.is_demo for r in records)}; "
              f"High: {sum(r.priority == 'High' and not r.is_demo for r in records)}; "
              f"Declared assets: {len(list_assets())}")
    elif args.command == "brief":
        destination = Path(args.output or "reports/daily_brief.md")
        destination.parent.mkdir(parents=True, exist_ok=True)
        content = digest(recent(list_threats(demo=False), args.brief_days))
        destination.write_text(content, encoding="utf-8")
        print(f"Saved live-source brief to {destination}")
    else:
        if not args.key:
            parser.error("--key is required for case export (e.g. --key demo:2)")
        matched = [record for record in list_threats() if record.key == args.key]
        if not matched:
            parser.error("No stored record has that source key. Run demo or sync first.")
        packet = evidence_packet(matched[0], list_assets())
        content = packet_json(packet) if args.format == "json" else packet_markdown(packet)
        extension = "json" if args.format == "json" else "md"
        destination = Path(args.output or f"reports/{packet['case_id']}.{extension}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
        print(f"Saved {packet['classification']} case to {destination}")


if __name__ == "__main__":
    main()
