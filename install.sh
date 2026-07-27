#!/usr/bin/env bash
# Sets up SecureDOT on Linux or macOS.
set -euo pipefail

echo "== SecureDOT setup =="

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is not installed. Install Python 3.9+ first." >&2
    exit 1
fi

if ! python3 -c "import tkinter" >/dev/null 2>&1; then
    echo "Tkinter is missing. Install it with:"
    echo "  Debian/Ubuntu: sudo apt install python3-tk"
    echo "  Fedora:        sudo dnf install python3-tkinter"
    echo "  macOS:         use the python.org installer (Homebrew's python often omits Tk)"
    exit 1
fi

if [ ! -f "data/VirusDataBaseHash.bav" ]; then
    echo "Signature database not found at data/VirusDataBaseHash.bav" >&2
    exit 1
fi

echo "All checks passed."
echo
echo "Launch the app with:"
echo "  python3 main.py"
