"""
SecureDOT — a lightweight, signature-based antivirus scanner.

Modules:
    hasher    – file hashing helpers
    database  – loads and queries the SHA-256 signature database
    scanner   – walks directories and matches files against the database
    remover   – safely deletes / quarantines confirmed threats
    gui       – the Tkinter desktop interface
"""

__version__ = "2.0.0"
