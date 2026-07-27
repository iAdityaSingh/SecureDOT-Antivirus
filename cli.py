#!/usr/bin/env python3
"""Command-line scanner — for headless machines or scripting.

Usage:
    python3 cli.py <path> [<path> ...]
    python3 cli.py ~/Downloads ~/Desktop
"""

from __future__ import annotations

import sys

from securedot.database import SignatureDatabase
from securedot.scanner import scan


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 1

    print("Loading signature database…")
    db = SignatureDatabase()
    print(f"Loaded {len(db):,} signatures.\n")

    def on_progress(filepath: str, count: int):
        print(f"\r  scanned {count:,} files…", end="", flush=True)

    summary = scan(argv, db, on_progress=on_progress)
    print(f"\r  scanned {summary.files_scanned:,} files.{' ' * 20}")

    if summary.threats:
        print(f"\n⚠  {len(summary.threats)} threat(s) found:\n")
        for result in summary.threats:
            print(f"  [{result.threat_name}]  {result.filepath}")
        print("\nRun the GUI (python3 main.py) to quarantine or delete these.")
        return 2

    print("\nNo threats found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
