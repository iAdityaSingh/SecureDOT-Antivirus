"""SecureDOT desktop GUI.

A single-window Tkinter app with Quick / Full / Custom scan modes, a live
status line, a results table, and quarantine/delete actions for anything
found. Scanning runs on a background thread (via a queue) so the window
never freezes, and every scan is cancellable.
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .database import SignatureDatabase
from .remover import delete as delete_files
from .remover import quarantine as quarantine_files
from .scanner import ScanResult, scan

BG = "#0f1720"
PANEL = "#16212c"
ACCENT = "#3ddc97"
ACCENT_DIM = "#2a9d73"
DANGER = "#ff5c5c"
TEXT = "#e6edf3"
MUTED = "#8b98a5"

# Directories a "Quick Scan" checks — the places malware most commonly lands.
QUICK_SCAN_TARGETS = [
    Path.home() / "Downloads",
    Path.home() / "Desktop",
    Path.home() / "Documents",
]


class SecureDotApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SecureDOT")
        self.root.geometry("880x600")
        self.root.minsize(760, 520)
        self.root.configure(bg=BG)

        self._queue: queue.Queue = queue.Queue()
        self._scan_thread: threading.Thread | None = None
        self._stop_requested = threading.Event()
        self._last_threats: list[ScanResult] = []
        self._db: SignatureDatabase | None = None
        self._db_error: str | None = None

        self._build_style()
        self._build_layout()
        self._load_database()
        self._poll_queue()

    # ------------------------------------------------------------------ UI

    def _build_style(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=("Segoe UI", 9))
        style.configure("Panel.TLabel", background=PANEL, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("Title.TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 20, "bold"))
        style.configure(
            "Accent.TButton",
            background=ACCENT,
            foreground="#04140d",
            font=("Segoe UI", 10, "bold"),
            padding=8,
            borderwidth=0,
        )
        style.map("Accent.TButton", background=[("active", ACCENT_DIM), ("disabled", "#3a4650")])
        style.configure(
            "Secondary.TButton",
            background=PANEL,
            foreground=TEXT,
            font=("Segoe UI", 10),
            padding=8,
            borderwidth=1,
        )
        style.map("Secondary.TButton", background=[("active", "#20303d")])
        style.configure(
            "Danger.TButton",
            background=DANGER,
            foreground="#2a0505",
            font=("Segoe UI", 10, "bold"),
            padding=8,
            borderwidth=0,
        )
        style.map("Danger.TButton", background=[("active", "#c24545")])
        style.configure("Horizontal.TProgressbar", background=ACCENT, troughcolor=PANEL, borderwidth=0)
        style.configure(
            "Results.Treeview",
            background=PANEL,
            fieldbackground=PANEL,
            foreground=TEXT,
            rowheight=26,
            borderwidth=0,
            font=("Segoe UI", 10),
        )
        style.configure("Results.Treeview.Heading", background="#1e2b38", foreground=MUTED, font=("Segoe UI", 9, "bold"))
        style.map("Results.Treeview", background=[("selected", "#20303d")])

    def _build_layout(self):
        header = ttk.Frame(self.root, style="TFrame", padding=(20, 18, 20, 8))
        header.pack(fill="x")

        title_row = ttk.Frame(header, style="TFrame")
        title_row.pack(fill="x")
        ttk.Label(title_row, text="SecureDOT", style="Title.TLabel").pack(side="left")
        self.db_status_var = tk.StringVar(value="Loading signature database…")
        ttk.Label(title_row, textvariable=self.db_status_var, style="Muted.TLabel").pack(side="right", pady=(10, 0))

        ttk.Label(header, text="Local, signature-based malware scanner", style="Muted.TLabel").pack(
            anchor="w", pady=(2, 0)
        )

        # Scan action buttons
        actions = ttk.Frame(self.root, style="TFrame", padding=(20, 10))
        actions.pack(fill="x")

        self.quick_btn = ttk.Button(actions, text="Quick Scan", style="Accent.TButton", command=self.run_quick_scan)
        self.quick_btn.pack(side="left", padx=(0, 8))

        self.full_btn = ttk.Button(actions, text="Full Scan", style="Secondary.TButton", command=self.run_full_scan)
        self.full_btn.pack(side="left", padx=8)

        self.custom_btn = ttk.Button(
            actions, text="Custom Scan…", style="Secondary.TButton", command=self.run_custom_scan
        )
        self.custom_btn.pack(side="left", padx=8)

        self.cancel_btn = ttk.Button(
            actions, text="Cancel", style="Secondary.TButton", command=self.cancel_scan, state="disabled"
        )
        self.cancel_btn.pack(side="left", padx=8)

        # Status / progress
        status_frame = ttk.Frame(self.root, style="TFrame", padding=(20, 4))
        status_frame.pack(fill="x")
        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(status_frame, textvariable=self.status_var, style="Muted.TLabel").pack(anchor="w")
        self.progress = ttk.Progressbar(status_frame, mode="indeterminate", style="Horizontal.TProgressbar")
        self.progress.pack(fill="x", pady=(6, 0))

        # Results table
        results_frame = ttk.Frame(self.root, style="Panel.TFrame", padding=10)
        results_frame.pack(fill="both", expand=True, padx=20, pady=(10, 10))

        columns = ("threat", "path")
        self.tree = ttk.Treeview(
            results_frame, columns=columns, show="headings", style="Results.Treeview", selectmode="extended"
        )
        self.tree.heading("threat", text="THREAT")
        self.tree.heading("path", text="FILE")
        self.tree.column("threat", width=220, anchor="w")
        self.tree.column("path", width=560, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Footer actions
        footer = ttk.Frame(self.root, style="TFrame", padding=(20, 0, 20, 16))
        footer.pack(fill="x")
        self.quarantine_btn = ttk.Button(
            footer, text="Quarantine Selected", style="Secondary.TButton", command=self.quarantine_selected, state="disabled"
        )
        self.quarantine_btn.pack(side="left")
        self.delete_btn = ttk.Button(
            footer, text="Delete Selected", style="Danger.TButton", command=self.delete_selected, state="disabled"
        )
        self.delete_btn.pack(side="left", padx=8)

    # ------------------------------------------------------------- database

    def _load_database(self):
        def worker():
            try:
                db = SignatureDatabase()
                self._queue.put(("db_loaded", db))
            except Exception as exc:  # noqa: BLE001 - surface any load error to the UI
                self._queue.put(("db_error", str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------ scanning

    def _start_scan(self, targets: list[Path]):
        if self._db is None:
            messagebox.showerror("SecureDOT", self._db_error or "Signature database is not loaded yet.")
            return
        if self._scan_thread is not None and self._scan_thread.is_alive():
            return

        self.tree.delete(*self.tree.get_children())
        self._last_threats = []
        self._set_scanning_state(True)
        self.status_var.set(f"Scanning {len(targets)} location(s)…")
        self.progress.start(12)
        self._stop_requested.clear()

        def on_progress(filepath: str, count: int):
            self._queue.put(("progress", filepath, count))

        def worker():
            summary = scan(
                targets,
                self._db,
                on_progress=on_progress,
                should_stop=lambda: self._stop_requested.is_set(),
            )
            self._queue.put(("done", summary))

        self._scan_thread = threading.Thread(target=worker, daemon=True)
        self._scan_thread.start()

    def run_quick_scan(self):
        targets = [p for p in QUICK_SCAN_TARGETS if p.exists()]
        if not targets:
            messagebox.showinfo("SecureDOT", "None of the default Quick Scan folders exist on this machine.")
            return
        self._start_scan(targets)

    def run_full_scan(self):
        if not messagebox.askyesno(
            "Full Scan",
            "A full scan walks your entire home directory and can take a while. Continue?",
        ):
            return
        self._start_scan([Path.home()])

    def run_custom_scan(self):
        chosen = filedialog.askdirectory(title="Choose a folder to scan")
        if not chosen:
            return
        self._start_scan([Path(chosen)])

    def cancel_scan(self):
        self._stop_requested.set()
        self.status_var.set("Cancelling…")

    def _set_scanning_state(self, scanning: bool):
        state = "disabled" if scanning else "normal"
        for btn in (self.quick_btn, self.full_btn, self.custom_btn):
            btn.configure(state=state)
        self.cancel_btn.configure(state=("normal" if scanning else "disabled"))
        if not scanning:
            self.progress.stop()

    # --------------------------------------------------------------- queue

    def _poll_queue(self):
        try:
            while True:
                message = self._queue.get_nowait()
                kind = message[0]

                if kind == "db_loaded":
                    self._db = message[1]
                    self.db_status_var.set(f"{len(self._db):,} signatures loaded")

                elif kind == "db_error":
                    self._db_error = message[1]
                    self.db_status_var.set("Signature database failed to load")
                    messagebox.showerror("SecureDOT", f"Could not load signature database:\n{message[1]}")

                elif kind == "progress":
                    _filepath, count = message[1], message[2]
                    self.status_var.set(f"Scanned {count:,} files…  {message[1]}")

                elif kind == "done":
                    summary = message[1]
                    self._last_threats = summary.threats
                    for result in summary.threats:
                        self.tree.insert("", "end", values=(result.threat_name, result.filepath))

                    self._set_scanning_state(False)
                    has_threats = bool(summary.threats)
                    self.quarantine_btn.configure(state=("normal" if has_threats else "disabled"))
                    self.delete_btn.configure(state=("normal" if has_threats else "disabled"))

                    if self._stop_requested.is_set():
                        self.status_var.set(f"Cancelled — {summary.files_scanned:,} files checked before stopping.")
                    elif has_threats:
                        self.status_var.set(
                            f"Scan complete — {summary.files_scanned:,} files checked, "
                            f"{len(summary.threats)} threat(s) found."
                        )
                    else:
                        self.status_var.set(
                            f"Scan complete — {summary.files_scanned:,} files checked, no threats found."
                        )
        except queue.Empty:
            pass
        self.root.after(80, self._poll_queue)

    # ---------------------------------------------------------- selection

    def _selected_results(self) -> list[ScanResult]:
        selected_paths = {self.tree.item(item, "values")[1] for item in self.tree.selection()}
        if not selected_paths:
            return self._last_threats
        return [t for t in self._last_threats if t.filepath in selected_paths]

    def quarantine_selected(self):
        results = self._selected_results()
        if not results:
            return
        if not messagebox.askyesno("Quarantine", f"Move {len(results)} file(s) to quarantine?"):
            return
        failed = quarantine_files(results)
        self._remove_handled_rows(results, failed)
        if failed:
            messagebox.showwarning("SecureDOT", f"{len(failed)} file(s) could not be quarantined.")

    def delete_selected(self):
        results = self._selected_results()
        if not results:
            return
        if not messagebox.askyesno(
            "Delete", f"Permanently delete {len(results)} file(s)? This cannot be undone."
        ):
            return
        failed = delete_files(results)
        self._remove_handled_rows(results, failed)
        if failed:
            messagebox.showwarning("SecureDOT", f"{len(failed)} file(s) could not be deleted.")

    def _remove_handled_rows(self, attempted: list[ScanResult], failed: list[str]):
        failed_set = set(failed)
        handled_paths = {r.filepath for r in attempted if r.filepath not in failed_set}
        for item in self.tree.get_children():
            if self.tree.item(item, "values")[1] in handled_paths:
                self.tree.delete(item)
        self._last_threats = [t for t in self._last_threats if t.filepath not in handled_paths]
        if not self._last_threats:
            self.quarantine_btn.configure(state="disabled")
            self.delete_btn.configure(state="disabled")


def main():
    root = tk.Tk()
    SecureDotApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
