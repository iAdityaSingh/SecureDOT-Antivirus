"""File hashing helpers used by the scanner."""

from __future__ import annotations

import hashlib
from pathlib import Path

# Read files in chunks so multi-GB files never get loaded into memory at once.
_CHUNK_SIZE = 1024 * 1024  # 1 MB


def sha256_hash(filepath: str | Path) -> str:
    """Return the lowercase hex SHA-256 digest of the file at ``filepath``.

    Raises the same exceptions ``open()`` would (FileNotFoundError,
    PermissionError, etc.) — callers are expected to handle those, since a
    scanner will inevitably hit locked or inaccessible files.
    """
    digest = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()
