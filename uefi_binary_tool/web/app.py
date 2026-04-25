#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Local browser UI for UEFI Binary Tool.

This uses only Python's standard library, so it works on Python builds that do
not include Tkinter.
"""

from __future__ import annotations

import contextlib
import html
import json
import os
import socket
import threading
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict
from urllib.parse import parse_qs

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

LANG = detect_language()

STATE_LOCK = threading.Lock()
STATE: Dict[str, Any] = {
    "running": False,
    "status": t("ready", LANG),
    "log": "",
    "result": None,
}


class StringLogWriter:
    """File-like writer that appends redirected operation output to web UI state."""

    def write(self, text: str) -> int:
        """Append redirected stdout/stderr text to the shared web log."""
        if text:
            with STATE_LOCK:
                STATE["log"] += text
        return len(text)

    def flush(self) -> None:
        """Provide a no-op flush method for stdout/stderr compatibility."""
        pass


def _json_response(handler: BaseHTTPRequestHandler, payload: Dict[str, Any], status: int = 200) -> None:
    """Send a JSON response with UTF-8 encoding."""
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _read_form(handler: BaseHTTPRequestHandler) -> Dict[str, str]:
    """Read an application/x-www-form-urlencoded request body into a dict."""
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length).decode("utf-8")
    parsed = parse_qs(raw)
    return {key: values[0] for key, values in parsed.items() if values}


def _run_job(form: Dict[str, str]) -> None:
    """Execute a requested operation in the background and update shared state."""
    vendor = form.get("vendor", "ASUS")
    mode = form.get("mode", "analyze")
    writer = StringLogWriter()

    try:
        with contextlib.redirect_stdout(writer), contextlib.redirect_stderr(writer):
            if mode == "analyze" and vendor == "ASUS":
                result = analyze_asus(form.get("analyze_file", "").strip())
            elif mode == "analyze":
                result = analyze_msi(form.get("analyze_file", "").strip())
            elif mode == "repack" and vendor == "ASUS":
                result = repack_asus(
                    form.get("original_file", "").strip(),
                    form.get("input_dir", "").strip(),
                    form.get("output_file", "").strip(),
                    writer.write,
                    LANG,
                )
            else:
                original_file = form.get("original_file", "").strip() or None
                result = repack_msi(
                    form.get("input_dir", "").strip(),
                    form.get("output_file", "").strip(),
                    original_file,
                    writer.write,
                    LANG,
                )
    except Exception as exc:
        writer.write(traceback.format_exc())
        result = OperationResult(False, str(exc))

    with STATE_LOCK:
        STATE["running"] = False
        STATE["status"] = result.message
        STATE["result"] = {
            "success": result.success,
            "message": result.message,
            "outputs": result.outputs,
        }
        STATE["log"] += f"\n[RESULT] {result.message}\n"
        if result.outputs:
            STATE["log"] += "[OUTPUT]\n"
            for path in result.outputs:
                STATE["log"] += f"  - {path}\n"


class WebHandler(BaseHTTPRequestHandler):
    """HTTP handler for the local browser-based UI and its small JSON API."""

    server_version = f"UEFIBinaryTool/{__version__}"

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default HTTP access logging."""
        return

    def do_GET(self) -> None:
        """Handle index and status API GET requests."""
        if self.path == "/" or self.path.startswith("/?"):
            self._serve_index()
            return
        if self.path == "/api/status":
            with STATE_LOCK:
                payload = dict(STATE)
            _json_response(self, payload)
            return
        _json_response(self, {"error": "not found"}, 404)

    def do_POST(self) -> None:
        """Handle operation-start POST requests."""
        if self.path == "/api/run":
            with STATE_LOCK:
                if STATE["running"]:
                    _json_response(self, {"error": t("already_running", LANG)}, 409)
                    return
                STATE["running"] = True
                STATE["status"] = t("job_running", LANG)
                STATE["log"] = ""
                STATE["result"] = None

            form = _read_form(self)
            thread = threading.Thread(target=_run_job, args=(form,), daemon=True)
            thread.start()
            _json_response(self, {"ok": True})
            return
        _json_response(self, {"error": "not found"}, 404)

    def _serve_index(self) -> None:
        """Render and send the localized single-page web UI."""
        replacements = {
            "__VERSION__": html.escape(__version__),
            "__APP_TITLE__": html.escape(t("app_title", LANG)),
            "__LANG__": html.escape(LANG),
            "__LANGUAGE_NAME__": html.escape(t("language_name", LANG)),
            "__VENDOR__": html.escape(t("vendor", LANG)),
            "__ANALYZE__": html.escape(t("analyze", LANG)),
            "__REPACK__": html.escape(t("repack", LANG)),
            "__BIOS_SECTION_FILE__": html.escape(t("bios_section_file", LANG)),
            "__ORIGINAL_BIOS_FILE__": html.escape(t("original_bios_file", LANG)),
            "__EXTRACTED_IMAGE_DIR__": html.escape(t("extracted_image_dir", LANG)),
            "__OUTPUT_FILE__": html.escape(t("output_file", LANG)),
            "__PATH_FILE_PLACEHOLDER__": html.escape(t("path_file_placeholder", LANG)),
            "__PATH_ORIGINAL_PLACEHOLDER__": html.escape(t("path_original_placeholder", LANG)),
            "__PATH_DIR_PLACEHOLDER__": html.escape(t("path_dir_placeholder", LANG)),
            "__AUTO_OUTPUT_PLACEHOLDER__": html.escape(t("auto_output_placeholder", LANG)),
            "__BROWSER_PATH_HINT__": html.escape(t("browser_path_hint", LANG)),
            "__START__": html.escape(t("start", LANG)),
            "__READY__": html.escape(t("ready", LANG)),
            "__RUN_FAILED__": html.escape(t("run_failed", LANG)),
        }
        html_body = INDEX_HTML
        for key, value in replacements.items():
            html_body = html_body.replace(key, value)
        body = html_body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


INDEX_HTML = """<!doctype html>
<html lang="__LANG__">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>__APP_TITLE__ __VERSION__</title>
  <style>
    :root {
      color-scheme: light;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f5f7fa;
      color: #17202a;
    }
    body { margin: 0; }
    main { max-width: 1060px; margin: 0 auto; padding: 24px; }
    h1 { font-size: 24px; margin: 0 0 18px; }
    section {
      background: white;
      border: 1px solid #d7dee8;
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 14px;
    }
    .grid { display: grid; grid-template-columns: 150px 1fr; gap: 10px; align-items: center; }
    label { font-weight: 650; }
    input, select, button {
      font: inherit;
      min-height: 36px;
      border-radius: 6px;
      border: 1px solid #b7c2d0;
      padding: 0 10px;
      box-sizing: border-box;
    }
    input, select { width: 100%; background: #fff; }
    button {
      background: #1f6feb;
      color: white;
      border-color: #1f6feb;
      cursor: pointer;
      padding: 0 16px;
    }
    button:disabled { opacity: .55; cursor: default; }
    .actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 12px; }
    .hint { color: #52616f; font-size: 13px; margin-top: 8px; }
    pre {
      min-height: 260px;
      max-height: 430px;
      overflow: auto;
      background: #111827;
      color: #e5e7eb;
      border-radius: 8px;
      padding: 12px;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .tabs { display: flex; gap: 8px; margin-bottom: 12px; }
    .tab { background: #e8eef7; color: #17202a; border-color: #c9d4e3; }
    .tab.active { background: #1f6feb; color: white; border-color: #1f6feb; }
    .hidden { display: none; }
    #status { font-weight: 650; }
  </style>
</head>
<body>
<main>
  <h1>__APP_TITLE__ __VERSION__</h1>
  <section>
    <div class="grid">
      <label for="vendor">__VENDOR__</label>
      <select id="vendor" name="vendor">
        <option>ASUS</option>
        <option>MSI</option>
      </select>
    </div>
  </section>
  <section>
    <div class="tabs">
      <button class="tab active" id="analyzeTab" type="button">__ANALYZE__</button>
      <button class="tab" id="repackTab" type="button">__REPACK__</button>
    </div>
    <form id="toolForm">
      <input type="hidden" name="mode" id="mode" value="analyze">
      <input type="hidden" name="vendor" id="vendorField" value="ASUS">
      <div id="analyzeFields" class="grid">
        <label for="analyze_file">__BIOS_SECTION_FILE__</label>
        <input id="analyze_file" name="analyze_file" placeholder="__PATH_FILE_PLACEHOLDER__">
      </div>
      <div id="repackFields" class="grid hidden">
        <label for="original_file">__ORIGINAL_BIOS_FILE__</label>
        <input id="original_file" name="original_file" placeholder="__PATH_ORIGINAL_PLACEHOLDER__">
        <label for="input_dir">__EXTRACTED_IMAGE_DIR__</label>
        <input id="input_dir" name="input_dir" placeholder="__PATH_DIR_PLACEHOLDER__">
        <label for="output_file">__OUTPUT_FILE__</label>
        <input id="output_file" name="output_file" placeholder="__AUTO_OUTPUT_PLACEHOLDER__">
      </div>
      <p class="hint" id="hint">__BROWSER_PATH_HINT__</p>
      <div class="actions">
        <button id="runButton" type="submit">__START__</button>
      </div>
    </form>
  </section>
  <section>
    <div id="status">__READY__</div>
    <pre id="log"></pre>
  </section>
</main>
<script>
const vendor = document.getElementById('vendor');
const vendorField = document.getElementById('vendorField');
const mode = document.getElementById('mode');
const analyzeTab = document.getElementById('analyzeTab');
const repackTab = document.getElementById('repackTab');
const analyzeFields = document.getElementById('analyzeFields');
const repackFields = document.getElementById('repackFields');
const form = document.getElementById('toolForm');
const statusEl = document.getElementById('status');
const logEl = document.getElementById('log');
const runButton = document.getElementById('runButton');

function setMode(nextMode) {
  mode.value = nextMode;
  analyzeTab.classList.toggle('active', nextMode === 'analyze');
  repackTab.classList.toggle('active', nextMode === 'repack');
  analyzeFields.classList.toggle('hidden', nextMode !== 'analyze');
  repackFields.classList.toggle('hidden', nextMode !== 'repack');
}
analyzeTab.onclick = () => setMode('analyze');
repackTab.onclick = () => setMode('repack');
vendor.onchange = () => { vendorField.value = vendor.value; };

form.onsubmit = async (event) => {
  event.preventDefault();
  vendorField.value = vendor.value;
  runButton.disabled = true;
  logEl.textContent = '';
  const response = await fetch('/api/run', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'},
    body: new URLSearchParams(new FormData(form))
  });
  if (!response.ok) {
    const data = await response.json();
    statusEl.textContent = data.error || '__RUN_FAILED__';
    runButton.disabled = false;
  }
};

async function poll() {
  const response = await fetch('/api/status');
  const data = await response.json();
  statusEl.textContent = data.status;
  logEl.textContent = data.log || '';
  logEl.scrollTop = logEl.scrollHeight;
  runButton.disabled = data.running;
}
setInterval(poll, 800);
poll();
</script>
</body>
</html>
"""


def _find_free_port() -> int:
    """Ask the OS for an available localhost TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def main() -> None:
    """Launch the local browser-based fallback UI."""
    port = _find_free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), WebHandler)
    url = f"http://127.0.0.1:{port}/"
    print(t("server_url", LANG, url=url))
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{t('server_stopped', LANG)}")
    finally:
        server.server_close()
