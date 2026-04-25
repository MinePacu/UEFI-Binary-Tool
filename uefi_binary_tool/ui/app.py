#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tkinter GUI for UEFI Binary Tool."""

from __future__ import annotations

import contextlib
import os
import queue
import sys
import threading
import traceback
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from typing import Callable, Optional

from uefi_binary_tool import __version__
from uefi_binary_tool.i18n import detect_language, t
from uefi_binary_tool.operations import (
    OperationResult,
    analyze_asus,
    analyze_msi,
    default_repack_output_path,
    repack_asus,
    repack_msi,
)


class QueueWriter:
    """File-like writer that forwards worker output into the Tkinter event queue."""

    def __init__(self, output_queue: "queue.Queue[tuple[str, object]]") -> None:
        """Create a stdout-compatible writer that forwards text to the UI queue."""
        self.output_queue = output_queue

    def write(self, text: str) -> int:
        """Forward text to the UI log queue and return the number of characters."""
        if text:
            self.output_queue.put(("log", text))
        return len(text)

    def flush(self) -> None:
        """Provide a no-op flush method for stdout/stderr compatibility."""
        pass


class UefiBinaryToolApp(ttk.Frame):
    """Main Tkinter application frame for analysis and repack workflows."""

    def __init__(self, master: tk.Tk) -> None:
        """Create the Tkinter application frame and initialize all UI state."""
        super().__init__(master, padding=12)
        self.master = master
        self.output_queue: "queue.Queue[tuple[str, object]]" = queue.Queue()
        self.worker: Optional[threading.Thread] = None
        self.running = False
        self.lang = detect_language()

        self.vendor_var = tk.StringVar(value="ASUS")
        self.analyze_file_var = tk.StringVar()
        self.repack_original_var = tk.StringVar()
        self.repack_dir_var = tk.StringVar()
        self.repack_output_var = tk.StringVar()
        self.status_var = tk.StringVar(value=t("ready", self.lang))

        self._configure_window()
        self._build_layout()
        self._poll_queue()

    def _configure_window(self) -> None:
        """Configure the root window size, title, and grid behavior."""
        self.master.title(f"{t('app_title', self.lang)} {__version__}")
        self.master.geometry("980x680")
        self.master.minsize(860, 560)
        self.master.columnconfigure(0, weight=1)
        self.master.rowconfigure(0, weight=1)
        self.grid(sticky="nsew")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

    def _build_layout(self) -> None:
        """Build the main application layout including tabs, log, and status bar."""
        top = ttk.Frame(self)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        top.columnconfigure(1, weight=1)

        ttk.Label(top, text=t("vendor", self.lang)).grid(row=0, column=0, sticky="w")
        vendor = ttk.Combobox(
            top,
            textvariable=self.vendor_var,
            values=("ASUS", "MSI"),
            width=12,
            state="readonly",
        )
        vendor.grid(row=0, column=1, sticky="w", padx=(8, 0))
        vendor.bind("<<ComboboxSelected>>", lambda _event: self._sync_vendor_fields())

        ttk.Label(
            top,
            text=t("ui_intro", self.lang),
        ).grid(row=0, column=2, sticky="e")

        self.notebook = ttk.Notebook(self)
        self.notebook.grid(row=1, column=0, sticky="ew")
        self._build_analyze_tab()
        self._build_repack_tab()

        log_frame = ttk.LabelFrame(self, text=t("work_log", self.lang), padding=8)
        log_frame.grid(row=2, column=0, sticky="nsew", pady=(10, 8))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_text = ScrolledText(log_frame, height=18, wrap="word", state="disabled")
        self.log_text.grid(row=0, column=0, sticky="nsew")

        bottom = ttk.Frame(self)
        bottom.grid(row=3, column=0, sticky="ew")
        bottom.columnconfigure(0, weight=1)
        ttk.Label(bottom, textvariable=self.status_var).grid(row=0, column=0, sticky="w")
        self.progress = ttk.Progressbar(bottom, mode="indeterminate", length=180)
        self.progress.grid(row=0, column=1, sticky="e", padx=(8, 0))

    def _build_analyze_tab(self) -> None:
        """Build controls for selecting and analyzing a BIOS/Section file."""
        frame = ttk.Frame(self.notebook, padding=12)
        frame.columnconfigure(1, weight=1)
        self.notebook.add(frame, text=t("analyze", self.lang))

        ttk.Label(frame, text=t("bios_section_file", self.lang)).grid(row=0, column=0, sticky="w", pady=6)
        ttk.Entry(frame, textvariable=self.analyze_file_var).grid(row=0, column=1, sticky="ew", padx=8)
        ttk.Button(frame, text=t("browse", self.lang), command=self._browse_analyze_file).grid(row=0, column=2)

        self.analyze_button = ttk.Button(frame, text=t("start_analyze", self.lang), command=self._start_analyze)
        self.analyze_button.grid(row=1, column=2, sticky="e", pady=(10, 0))

    def _build_repack_tab(self) -> None:
        """Build controls for selecting repack inputs and output path."""
        frame = ttk.Frame(self.notebook, padding=12)
        frame.columnconfigure(1, weight=1)
        self.notebook.add(frame, text=t("repack", self.lang))

        ttk.Label(frame, text=t("original_bios_file", self.lang)).grid(row=0, column=0, sticky="w", pady=6)
        ttk.Entry(frame, textvariable=self.repack_original_var).grid(row=0, column=1, sticky="ew", padx=8)
        ttk.Button(frame, text=t("browse", self.lang), command=self._browse_repack_original).grid(row=0, column=2)

        ttk.Label(frame, text=t("extracted_image_dir", self.lang)).grid(row=1, column=0, sticky="w", pady=6)
        ttk.Entry(frame, textvariable=self.repack_dir_var).grid(row=1, column=1, sticky="ew", padx=8)
        ttk.Button(frame, text=t("browse", self.lang), command=self._browse_repack_dir).grid(row=1, column=2)

        ttk.Label(frame, text=t("output_file", self.lang)).grid(row=2, column=0, sticky="w", pady=6)
        ttk.Entry(frame, textvariable=self.repack_output_var).grid(row=2, column=1, sticky="ew", padx=8)
        ttk.Button(frame, text=t("save_location", self.lang), command=self._browse_output_file).grid(row=2, column=2)

        self.repack_hint = ttk.Label(frame, text="")
        self.repack_hint.grid(row=3, column=0, columnspan=3, sticky="w", pady=(6, 0))

        self.repack_button = ttk.Button(frame, text=t("start_repack", self.lang), command=self._start_repack)
        self.repack_button.grid(row=4, column=2, sticky="e", pady=(10, 0))
        self._sync_vendor_fields()

    def _sync_vendor_fields(self) -> None:
        """Update vendor-specific helper text in the repack tab."""
        vendor = self.vendor_var.get()
        if vendor == "MSI":
            self.repack_hint.configure(text=t("msi_repack_hint", self.lang))
        else:
            self.repack_hint.configure(text=t("asus_repack_hint", self.lang))

    def _browse_analyze_file(self) -> None:
        """Open a file picker and store the selected analysis file path."""
        path = filedialog.askopenfilename(title=t("choose_analyze_file", self.lang))
        if path:
            self.analyze_file_var.set(path)

    def _browse_repack_original(self) -> None:
        """Open a file picker and store the selected original BIOS path."""
        path = filedialog.askopenfilename(title=t("choose_original_file", self.lang))
        if path:
            self.repack_original_var.set(path)
            if not self.repack_output_var.get():
                self.repack_output_var.set(default_repack_output_path(path, self.vendor_var.get()))

    def _browse_repack_dir(self) -> None:
        """Open a directory picker and store the selected extracted-image folder."""
        path = filedialog.askdirectory(title=t("choose_extracted_dir", self.lang))
        if path:
            self.repack_dir_var.set(path)
            if not self.repack_output_var.get() and self.vendor_var.get() == "MSI":
                self.repack_output_var.set(default_repack_output_path(path, "msi"))

    def _browse_output_file(self) -> None:
        """Open a save dialog and store the selected repack output path."""
        path = filedialog.asksaveasfilename(
            title=t("choose_output_file", self.lang),
            defaultextension=".bin",
            filetypes=(("Binary files", "*.bin"), ("All files", "*.*")),
        )
        if path:
            self.repack_output_var.set(path)

    def _start_analyze(self) -> None:
        """Start the vendor-specific analysis operation from current form values."""
        vendor = self.vendor_var.get()
        file_path = self.analyze_file_var.get().strip()
        if vendor == "ASUS":
            operation = lambda: analyze_asus(file_path)
        else:
            operation = lambda: analyze_msi(file_path)
        self._run_operation(t("analyze_label", self.lang, vendor=vendor), operation)

    def _start_repack(self) -> None:
        """Start the vendor-specific repack operation from current form values."""
        vendor = self.vendor_var.get()
        original_file = self.repack_original_var.get().strip()
        input_dir = self.repack_dir_var.get().strip()
        output_file = self.repack_output_var.get().strip()

        if vendor == "ASUS":
            operation = lambda: repack_asus(original_file, input_dir, output_file)
        else:
            original_or_none = original_file or None
            operation = lambda: repack_msi(input_dir, output_file, original_or_none)
        self._run_operation(t("repack_label", self.lang, vendor=vendor), operation)

    def _run_operation(self, label: str, operation: Callable[[], OperationResult]) -> None:
        """Run an operation on a worker thread while streaming logs to the UI."""
        if self.running:
            messagebox.showinfo(t("busy_title", self.lang), t("busy_message", self.lang))
            return

        self._clear_log()
        self._append_log(f"[{t('start', self.lang).upper()}] {label}\n")
        self.running = True
        self.status_var.set(t("operation_running", self.lang, label=label))
        self.progress.start(10)
        self._set_buttons_state("disabled")

        def target() -> None:
            """Execute the operation and enqueue its final result for the UI thread."""
            writer = QueueWriter(self.output_queue)
            try:
                with contextlib.redirect_stdout(writer), contextlib.redirect_stderr(writer):
                    result = operation()
                self.output_queue.put(("result", result))
            except Exception as exc:
                writer.write(traceback.format_exc())
                self.output_queue.put(("result", OperationResult(False, str(exc))))

        self.worker = threading.Thread(target=target, daemon=True)
        self.worker.start()

    def _poll_queue(self) -> None:
        """Process pending log and result events from the worker thread."""
        try:
            while True:
                kind, payload = self.output_queue.get_nowait()
                if kind == "log":
                    self._append_log(str(payload))
                elif kind == "result":
                    self._finish_operation(payload)  # type: ignore[arg-type]
        except queue.Empty:
            pass
        self.after(80, self._poll_queue)

    def _finish_operation(self, result: OperationResult) -> None:
        """Update UI state after a worker operation finishes."""
        self.running = False
        self.progress.stop()
        self._set_buttons_state("normal")
        self.status_var.set(result.message)

        self._append_log(f"\n[{t('result', self.lang).upper()}] {result.message}\n")
        if result.outputs:
            self._append_log(f"[{t('outputs', self.lang).upper()}]\n")
            for path in result.outputs:
                self._append_log(f"  - {path}\n")

        if result.success:
            messagebox.showinfo(t("completed_title", self.lang), result.message)
        else:
            messagebox.showerror(t("failed_title", self.lang), result.message)

    def _set_buttons_state(self, state: str) -> None:
        """Enable or disable operation buttons."""
        self.analyze_button.configure(state=state)
        self.repack_button.configure(state=state)

    def _append_log(self, text: str) -> None:
        """Append text to the read-only log widget."""
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _clear_log(self) -> None:
        """Clear all text from the log widget."""
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")


def main() -> None:
    """Launch the Tkinter UI application."""
    if os.name == "nt":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except Exception:
            pass

    root = tk.Tk()
    try:
        ttk.Style().theme_use("clam")
    except tk.TclError:
        pass
    UefiBinaryToolApp(root)
    root.mainloop()
