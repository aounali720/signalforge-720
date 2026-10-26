"""Spreadsheet-safe export of third-party strings from untrusted news metadata."""
from __future__ import annotations
import csv
from io import StringIO


def safe_cell(value: object) -> object:
    if not isinstance(value, str):
        return value
    # CSV files may be opened in Excel: avoid interpreting uncontrolled feed text
    # as a formula, even when it begins with whitespace or a control character.
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value


def safe_csv(rows: list[dict]) -> str:
    if not rows:
        return ""
    output = StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    for row in rows:
        writer.writerow({k: safe_cell(v) for k, v in row.items()})
    return output.getvalue()
