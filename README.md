# SecureDOT

A lightweight, offline, signature-based malware scanner with a desktop GUI, built in pure Python.

SecureDOT hashes files with SHA-256 and checks them against a local database of ~184,000 known-malware hashes. Everything runs locally — no files or hashes are ever sent anywhere.

> **Not a replacement for a real-time antivirus product.** SecureDOT only catches malware whose exact file hash is already in its database (no heuristics, no behavioral detection). Think of it as a fast, transparent, on-demand hash scanner — good for checking suspicious downloads, learning how AV signature-matching works, or as a base to build on.

## Features

- **Quick Scan** — checks the folders malware most commonly lands in (Downloads, Desktop, Documents).
- **Full Scan** — walks your entire home directory.
- **Custom Scan** — pick any folder or file.
- **Fast lookups** — the ~184k-entry signature database loads into an in-memory hash map once at startup, so each file lookup is O(1) instead of a linear scan.
- **Non-blocking UI** — scanning runs on a background thread; the window stays responsive and scans are cancellable mid-run.
- **Quarantine, not just delete** — flagged files are moved to a local quarantine folder by default so a false positive doesn't cost you a real file. Permanent delete is available too, behind a confirmation dialog.
- **CLI mode** — `cli.py` for headless / scriptable scanning.

## Screenshots

The GUI is a dark-themed single window: scan buttons across the top, a live status line with progress bar, a sortable results table, and quarantine/delete actions at the bottom.

## Installation

**Requirements:** Python 3.9+ with Tk support (Tkinter). No third-party packages — everything used is in the standard library.

```bash
git clone https://github.com/iAdityaSingh/SecureDOT-Antivirus.git
cd SecureDOT-Antivirus

# Linux / macOS
./install.sh

# Windows
install.bat
```

The install script just checks that Python, Tkinter, and the signature database are all present — there's nothing to actually download or compile.

## Usage

**GUI:**

```bash
python3 main.py
```

Pick Quick Scan, Full Scan, or Custom Scan. Results appear in the table as they're found; select one or more rows (or leave nothing selected to act on all results) and click **Quarantine Selected** or **Delete Selected**.

**Command line:**

```bash
python3 cli.py ~/Downloads ~/Desktop
```

Exits with code `2` if any threats were found, `0` if the scan was clean — handy for scripting or CI.

## Verifying it actually works

Don't test a scanner with real malware. The industry-standard, completely harmless way to confirm any antivirus is detecting things is the [EICAR test file](https://en.wikipedia.org/wiki/EICAR_test_file) — a plain text string every AV vendor agrees to flag as a "virus" for testing purposes, with no actual malicious payload. To test SecureDOT you'd need the EICAR string's hash added to `data/VirusDataBaseHash.bav` (it isn't included by default, since EICAR is meant to be downloaded fresh from eicar.org rather than redistributed).

## How it works

```
securedot/
├── hasher.py     # SHA-256 file hashing (chunked, so large files don't blow up memory)
├── database.py   # Loads VirusDataBaseHash.bav into an in-memory hash map
├── scanner.py    # Walks a path, hashes each file, checks it against the database
├── remover.py    # Quarantine / delete actions, only ever called after user confirmation
└── gui.py        # Tkinter desktop app
```

The signature file format (`data/VirusDataBaseHash.bav`) is one entry per line:

```
<64-char lowercase sha256 hash>:<threat name>
```

## What changed from the original version

This started as a set of standalone scripts (`neuron.py`, `uni-bit.py`, `deff.py`, `detectmalwaresha.py`) written while learning. The rewrite keeps the same core idea — hash files, compare against a known-bad list — but fixes several real problems:

- **O(n) → O(1) lookups.** The original re-read `virusHash.txt` and `virusInfo.txt` line-by-line for every single file being scanned. With ~190k signatures that made scanning any real directory painfully slow. The database now loads once into a dict.
- **No hardcoded paths.** `virusRemover()` used to have a specific Windows path (`C:\Users\adity\...`) baked in and would delete files immediately with zero confirmation. Deletion now always requires explicit user confirmation, and quarantining (safe, reversible) is the default over permanent delete.
- **A working GUI.** `neuron.py` opened an empty Tkinter window with a title and nothing else. There's now an actual interface: scan controls, live progress, a results table, and quarantine/delete actions.
- **No frozen UI during a scan.** Scanning now runs on a background thread instead of blocking the main thread.
- **Removed derived/duplicate data files.** `virusHash.txt` and `virusInfo.txt` were ~30 MB of data mechanically derived from `VirusDataBaseHash.bav` by `deff.py` — that's now parsed directly at runtime, so there's nothing to regenerate or keep in sync.
- **Removed a bundled keylogger sample.** The original repo included a full working keylogger's source (`keylogger-master.zip`), presumably as a malware test sample. It's been removed — shipping working keylogger source in a public repo is a real distribution/legal risk regardless of intent, and it added ~16 MB for no functional benefit (the scanner only ever needs *hashes*, not live samples).

## Roadmap ideas

- Scheduled/background scanning
- A "Recently quarantined" view with a restore button
- Pulling signature updates from a public hash feed (e.g. MalwareBazaar) instead of a static file
- Packaging as a standalone executable (PyInstaller) for non-technical users

## Contributing

1. Fork the repo
2. Create a branch for your change
3. Open a pull request describing what and why

## License

MIT — see [LICENSE](LICENSE).
