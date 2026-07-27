"""Loads the SHA-256 signature database (``VirusDataBaseHash.bav``).

The original project stored the database as parallel files
(``VirusDataBaseHash.bav`` → split into ``virusHash.txt`` / ``virusInfo.txt``
by a separate script, then re-read line-by-line for every single lookup).
That meant every scanned file did an O(n) linear scan through ~190,000
entries. This module parses the .bav file once into a dict, so a lookup is
O(1) and no derived files need to be committed to the repo.

File format, one signature per line::

    <64-char lowercase sha256 hex>:<threat name>
"""

from __future__ import annotations

from pathlib import Path

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "VirusDataBaseHash.bav"


class SignatureDatabase:
    def __init__(self, path: str | Path = DEFAULT_DB_PATH):
        self.path = Path(path)
        self._signatures: dict[str, str] = {}
        self.load()

    def load(self) -> int:
        """(Re)load the database from disk. Returns the number of signatures loaded."""
        self._signatures.clear()
        if not self.path.exists():
            raise FileNotFoundError(
                f"Signature database not found at {self.path}. "
                "Did you move or delete the data/ folder?"
            )

        with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                file_hash, _, threat_name = line.partition(":")
                file_hash = file_hash.strip().lower()
                threat_name = threat_name.strip()
                if len(file_hash) == 64 and threat_name:
                    self._signatures[file_hash] = threat_name

        return len(self._signatures)

    def lookup(self, file_hash: str) -> str | None:
        """Return the threat name for a hash, or None if it's not a known signature."""
        return self._signatures.get(file_hash.lower())

    def __len__(self) -> int:
        return len(self._signatures)

    def __contains__(self, file_hash: str) -> bool:
        return file_hash.lower() in self._signatures
