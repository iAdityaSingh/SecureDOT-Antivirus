"""Removes or quarantines files flagged by a scan.

The original ``virusRemover`` deleted files immediately with no
confirmation and a hardcoded path. This version never deletes anything by
itself — the caller (GUI or CLI) must explicitly confirm — and prefers
quarantining (move to an isolated folder) over permanent deletion so a
false positive doesn't cost the user a real file.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from .scanner import ScanResult

DEFAULT_QUARANTINE_DIR = Path.home() / ".securedot" / "quarantine"


def quarantine(results: list[ScanResult], quarantine_dir: str | Path = DEFAULT_QUARANTINE_DIR) -> list[str]:
    """Move each flagged file into the quarantine folder. Returns paths that failed to move."""
    quarantine_dir = Path(quarantine_dir)
    quarantine_dir.mkdir(parents=True, exist_ok=True)

    failed: list[str] = []
    for result in results:
        src = Path(result.filepath)
        if not src.exists():
            continue
        dest = quarantine_dir / f"{src.name}.quarantined"
        # Avoid clobbering an existing quarantined file with the same name.
        counter = 1
        while dest.exists():
            dest = quarantine_dir / f"{src.name}.{counter}.quarantined"
            counter += 1
        try:
            shutil.move(str(src), str(dest))
        except OSError:
            failed.append(result.filepath)
    return failed


def delete(results: list[ScanResult]) -> list[str]:
    """Permanently delete each flagged file. Returns paths that failed to delete."""
    failed: list[str] = []
    for result in results:
        try:
            Path(result.filepath).unlink(missing_ok=True)
        except OSError:
            failed.append(result.filepath)
    return failed
