"""Walks directories and matches files against the signature database."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Iterator

from .database import SignatureDatabase
from .hasher import sha256_hash


@dataclass
class ScanResult:
    filepath: str
    threat_name: str


@dataclass
class ScanSummary:
    files_scanned: int
    files_skipped: int
    threats: list[ScanResult]


def iter_files(paths: Iterable[str | Path]) -> Iterator[str]:
    """Yield every file path under the given root path(s), recursively."""
    for root in paths:
        root = Path(root)
        if root.is_file():
            yield str(root)
            continue
        for dirpath, _dirnames, filenames in os.walk(root):
            for name in filenames:
                yield os.path.join(dirpath, name)


def scan(
    paths: Iterable[str | Path],
    database: SignatureDatabase,
    on_progress: Callable[[str, int], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> ScanSummary:
    """Scan every file under ``paths`` against ``database``.

    Args:
        paths: one or more files/directories to scan.
        database: a loaded SignatureDatabase.
        on_progress: optional callback ``(current_filepath, files_scanned_so_far)``,
            called after each file — useful for updating a GUI progress bar.
        should_stop: optional callback polled between files; return True to
            cancel the scan early (e.g. the user clicked "Cancel").

    Returns:
        ScanSummary with counts and the list of matched threats.
    """
    threats: list[ScanResult] = []
    scanned = 0
    skipped = 0

    for filepath in iter_files(paths):
        if should_stop is not None and should_stop():
            break

        try:
            file_hash = sha256_hash(filepath)
        except (OSError, PermissionError):
            # Locked / inaccessible files are common (system files, files in
            # use by another process) — skip rather than aborting the scan.
            skipped += 1
            continue

        scanned += 1
        threat_name = database.lookup(file_hash)
        if threat_name is not None:
            threats.append(ScanResult(filepath=filepath, threat_name=threat_name))

        if on_progress is not None:
            on_progress(filepath, scanned)

    return ScanSummary(files_scanned=scanned, files_skipped=skipped, threats=threats)
