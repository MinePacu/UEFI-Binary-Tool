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
import re
import socket
import tempfile
import threading
import traceback
import webbrowser
from email.parser import BytesParser
from email.policy import default
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

from uefi_binary_tool import __version__
from uefi_binary_tool.i18n import detect_language, t
from uefi_binary_tool.operations import (
    OperationResult,
    analyze_asus,
    analyze_msi,
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

WIKI_PAGES = (
    ("Home", "UEFI Binary Tool Wiki", "UEFI Binary Tool Wiki"),
    ("GUI-Usage", "GUI 사용법", "GUI Usage"),
    ("ASUS-Workflow", "ASUS 분석 및 리패킹", "ASUS Analysis and Repacking"),
    ("MSI-Workflow", "MSI 분석 및 리패킹", "MSI Analysis and Repacking"),
    ("CLI-and-Batch", "CLI 및 Windows 배치 파일", "CLI and Windows Batch Files"),
    ("Troubleshooting", "문제 해결", "Troubleshooting"),
)
WIKI_SLUGS = {slug for slug, _ko, _en in WIKI_PAGES}
UPLOAD_ROOT = Path(tempfile.gettempdir()) / "uefi_binary_tool_uploads"
WEB_OUTPUT_DIR = Path.cwd() / "web_outputs"


class StringLogWriter:
    """File-like writer that appends redirected operation output to web UI state."""

    def write(self, text: str) -> int:
        """Append redirected stdout/stderr text to the shared web log.

        Args:
            text: Log text written by redirected operation output.

        Returns:
            Number of characters accepted.
        """
        if text:
            with STATE_LOCK:
                STATE["log"] += text
        return len(text)

    def flush(self) -> None:
        """Provide a no-op flush method for stdout/stderr compatibility."""
        pass


def _json_response(handler: BaseHTTPRequestHandler, payload: Dict[str, Any], status: int = 200) -> None:
    """Send a JSON response with UTF-8 encoding.

    Args:
        handler: Active HTTP request handler used to write the response.
        payload: JSON-serializable response object.
        status: HTTP status code to send.
    """
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _safe_upload_name(name: str) -> Path:
    """Return a safe relative path for a browser-uploaded file name.

    Args:
        name: Browser-provided filename, possibly including relative folder segments.

    Returns:
        Sanitized relative path safe to append under the upload directory.
    """
    parts = []
    for part in Path(name.replace("\\", "/")).parts:
        if part in ("", ".", "..") or part.startswith("/"):
            continue
        parts.append(part)
    return Path(*parts) if parts else Path("upload.bin")


def _save_uploaded_file(upload_dir: Path, filename: str, payload: bytes) -> str:
    """Save one uploaded file and return its local path.

    Args:
        upload_dir: Base directory for this upload field.
        filename: Browser-provided filename or relative folder path.
        payload: Raw uploaded file bytes.

    Returns:
        Absolute path to the saved local file as a string.
    """
    target = upload_dir / _safe_upload_name(filename)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    return str(target)


def _read_urlencoded_form(handler: BaseHTTPRequestHandler) -> Dict[str, str]:
    """Read an application/x-www-form-urlencoded request body into a dict.

    Args:
        handler: Active HTTP request handler containing the request body.

    Returns:
        Mapping of form field names to their first submitted value.
    """
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length).decode("utf-8")
    parsed = parse_qs(raw)
    return {key: values[0] for key, values in parsed.items() if values}


def _read_multipart_form(handler: BaseHTTPRequestHandler) -> Dict[str, str]:
    """Read a multipart form and materialize browser-selected files locally.

    Args:
        handler: Active HTTP request handler containing multipart form data.

    Returns:
        Mapping of normalized form fields to text values or saved local file paths.
    """
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length)
    content_type = handler.headers.get("Content-Type", "")
    message = BytesParser(policy=default).parsebytes(
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8") + raw
    )
    form: Dict[str, str] = {}
    upload_dir = Path(tempfile.mkdtemp(prefix="job_", dir=UPLOAD_ROOT))
    uploaded_dirs: Dict[str, Path] = {}

    for part in message.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if filename:
            saved_path = _save_uploaded_file(upload_dir / name, filename, payload)
            if name == "input_dir_upload":
                uploaded_dirs[name] = upload_dir / name
            elif name == "analyze_file_upload":
                form["analyze_file"] = saved_path
            elif name == "original_file_upload":
                form["original_file"] = saved_path
            else:
                form[name] = saved_path
        else:
            value = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            if value:
                form[name] = value

    if "input_dir_upload" in uploaded_dirs:
        form["input_dir"] = str(uploaded_dirs["input_dir_upload"])
    form["_upload_dir"] = str(upload_dir)
    return form


def _read_form(handler: BaseHTTPRequestHandler) -> Dict[str, str]:
    """Read a browser form request into a dict.

    Args:
        handler: Active HTTP request handler containing either multipart or URL-encoded data.

    Returns:
        Mapping of form field names to text values or saved upload paths.
    """
    content_type = handler.headers.get("Content-Type", "")
    if content_type.startswith("multipart/form-data"):
        UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
        return _read_multipart_form(handler)
    return _read_urlencoded_form(handler)


def _wiki_dir() -> Path:
    """Return the repository wiki directory used by the local web UI.

    Returns:
        Path to the top-level ``wiki`` directory.
    """
    return Path(__file__).resolve().parents[2] / "wiki"


def _wiki_base_slug(slug: str) -> str:
    """Normalize a localized wiki slug to the base wiki document name.

    Args:
        slug: Requested wiki slug or Markdown filename.

    Returns:
        Base wiki slug without locale suffix or extension.
    """
    base = slug.strip("/").removesuffix(".md")
    if base.endswith("-en"):
        base = base[:-3]
    return base or "Home"


def _wiki_file_for_slug(slug: str) -> Path | None:
    """Resolve a wiki slug to the localized Markdown file, if it is known.

    Args:
        slug: Requested wiki slug from the URL.

    Returns:
        Localized Markdown path, or None when the slug is not supported.
    """
    base = _wiki_base_slug(slug)
    if base not in WIKI_SLUGS:
        return None
    suffix = "-en" if LANG == "en" else ""
    return _wiki_dir() / f"{base}{suffix}.md"


def _wiki_nav_html(active_slug: str) -> str:
    """Render the localized wiki page navigation.

    Args:
        active_slug: Wiki slug that should be marked as selected.

    Returns:
        HTML anchor list for the wiki sidebar navigation.
    """
    active = _wiki_base_slug(active_slug)
    items = []
    for slug, ko_label, en_label in WIKI_PAGES:
        label = en_label if LANG == "en" else ko_label
        class_name = "active" if slug == active else ""
        items.append(f'<a class="{class_name}" href="/wiki/{html.escape(slug)}">{html.escape(label)}</a>')
    return "\n".join(items)


def _render_inline_markdown(text: str) -> str:
    """Render a small, safe subset of inline Markdown.

    Args:
        text: Plain Markdown text containing optional inline code or links.

    Returns:
        HTML-safe inline content.
    """
    escaped = html.escape(text)

    def code_repl(match: re.Match[str]) -> str:
        """Render one inline-code regex match.

        Args:
            match: Regex match containing the code text in group 1.

        Returns:
            HTML ``code`` element for the matched text.
        """
        return f"<code>{match.group(1)}</code>"

    def link_repl(match: re.Match[str]) -> str:
        """Render one Markdown-link regex match.

        Args:
            match: Regex match containing link label and destination.

        Returns:
            HTML anchor element, with wiki-relative links normalized.
        """
        label = match.group(1)
        href = match.group(2).strip()
        if not href.startswith(("http://", "https://", "#", "/")):
            href = f"/wiki/{href.removesuffix('.md')}"
        return f'<a href="{html.escape(href, quote=True)}">{label}</a>'

    escaped = re.sub(r"`([^`]+)`", code_repl, escaped)
    escaped = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", link_repl, escaped)
    return escaped


def _render_markdown(markdown: str) -> str:
    """Render the wiki Markdown subset used by the bundled help pages.

    Args:
        markdown: Raw Markdown source for one wiki page.

    Returns:
        HTML body content for the supported Markdown subset.
    """
    blocks: list[str] = []
    paragraph: list[str] = []
    list_type: str | None = None
    table_rows: list[list[str]] = []
    in_code = False
    code_lines: list[str] = []

    def flush_paragraph() -> None:
        """Append the buffered paragraph lines to the output blocks."""
        nonlocal paragraph
        if paragraph:
            text = " ".join(line.strip() for line in paragraph)
            blocks.append(f"<p>{_render_inline_markdown(text)}</p>")
            paragraph = []

    def flush_list() -> None:
        """Close the currently open ordered or unordered list."""
        nonlocal list_type
        if list_type:
            blocks.append(f"</{list_type}>")
            list_type = None

    def flush_table() -> None:
        """Append the buffered Markdown table rows to the output blocks."""
        nonlocal table_rows
        if not table_rows:
            return
        header, *body_rows = table_rows
        head = "".join(f"<th>{_render_inline_markdown(cell)}</th>" for cell in header)
        rows = [f"<thead><tr>{head}</tr></thead>"]
        if body_rows:
            body = []
            for row in body_rows:
                cells = "".join(f"<td>{_render_inline_markdown(cell)}</td>" for cell in row)
                body.append(f"<tr>{cells}</tr>")
            rows.append(f"<tbody>{''.join(body)}</tbody>")
        blocks.append(f"<table>{''.join(rows)}</table>")
        table_rows = []

    def flush_all() -> None:
        """Flush all pending paragraph, list, and table buffers."""
        flush_paragraph()
        flush_list()
        flush_table()

    for raw_line in markdown.splitlines():
        line = raw_line.rstrip()
        if line.startswith("```"):
            flush_all()
            if in_code:
                blocks.append(f"<pre><code>{html.escape(chr(10).join(code_lines))}</code></pre>")
                code_lines = []
                in_code = False
            else:
                in_code = True
            continue
        if in_code:
            code_lines.append(line)
            continue
        if not line.strip():
            flush_all()
            continue
        if line.startswith("|") and line.endswith("|"):
            flush_paragraph()
            flush_list()
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            if all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
                continue
            table_rows.append(cells)
            continue
        flush_table()
        heading = re.match(r"^(#{1,3})\s+(.+)$", line)
        if heading:
            flush_paragraph()
            flush_list()
            level = len(heading.group(1))
            blocks.append(f"<h{level}>{_render_inline_markdown(heading.group(2))}</h{level}>")
            continue
        if line.startswith("> "):
            flush_paragraph()
            flush_list()
            blocks.append(f"<blockquote>{_render_inline_markdown(line[2:].strip())}</blockquote>")
            continue
        unordered = re.match(r"^[-*]\s+(.+)$", line)
        ordered = re.match(r"^\d+\.\s+(.+)$", line)
        if unordered or ordered:
            flush_paragraph()
            next_type = "ul" if unordered else "ol"
            if list_type != next_type:
                flush_list()
                blocks.append(f"<{next_type}>")
                list_type = next_type
            item = (unordered or ordered).group(1)
            blocks.append(f"<li>{_render_inline_markdown(item)}</li>")
            continue
        paragraph.append(line)

    if in_code:
        blocks.append(f"<pre><code>{html.escape(chr(10).join(code_lines))}</code></pre>")
    flush_all()
    return "\n".join(blocks)


def _web_output_path(source_path: str, vendor: str) -> str:
    """Build a persistent default output path for uploaded repack jobs.

    Args:
        source_path: Uploaded source file or directory path used to derive a name.
        vendor: Vendor name, such as "asus" or "msi".

    Returns:
        Path under ``web_outputs`` for the generated repacked binary.
    """
    WEB_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    source = Path(source_path)
    stem = source.stem if source.is_file() else source.name
    stem = stem or "repacked"
    return str(WEB_OUTPUT_DIR / f"{stem}_{vendor.lower()}_repacked.bin")


def _run_job(form: Dict[str, str]) -> None:
    """Execute a requested operation in the background and update shared state.

    Args:
        form: Normalized request form containing vendor, mode, paths, and upload metadata.
    """
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
                output_file = form.get("output_file", "").strip()
                if not output_file and form.get("_upload_dir"):
                    output_file = _web_output_path(form.get("original_file", "").strip(), "asus")
                result = repack_asus(
                    form.get("original_file", "").strip(),
                    form.get("input_dir", "").strip(),
                    output_file,
                    writer.write,
                    LANG,
                )
            else:
                original_file = form.get("original_file", "").strip() or None
                output_file = form.get("output_file", "").strip()
                if not output_file and form.get("_upload_dir"):
                    output_file = _web_output_path(form.get("input_dir", "").strip(), "msi")
                result = repack_msi(
                    form.get("input_dir", "").strip(),
                    output_file,
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
        """Suppress default HTTP access logging.

        Args:
            format: Access-log format string supplied by BaseHTTPRequestHandler.
            *args: Format arguments supplied by BaseHTTPRequestHandler.
        """
        return

    def do_GET(self) -> None:
        """Handle index, wiki, and status API GET requests.

        The request path and query string are read from ``self.path``.
        """
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._serve_index()
            return
        if parsed.path == "/api/status":
            with STATE_LOCK:
                payload = dict(STATE)
            _json_response(self, payload)
            return
        if parsed.path == "/wiki" or parsed.path == "/wiki/":
            self._serve_wiki("Home")
            return
        if parsed.path.startswith("/wiki/"):
            self._serve_wiki(parsed.path.removeprefix("/wiki/"))
            return
        _json_response(self, {"error": "not found"}, 404)

    def do_POST(self) -> None:
        """Handle operation-start POST requests.

        The request body is read from ``self.rfile`` when ``self.path`` is ``/api/run``.
        """
        if self.path == "/api/run":
            with STATE_LOCK:
                if STATE["running"]:
                    _json_response(self, {"error": t("already_running", LANG)}, 409)
                    return
                STATE["running"] = True
                STATE["status"] = t("job_running", LANG)
                STATE["log"] = ""
                STATE["result"] = None

            try:
                form = _read_form(self)
            except Exception as exc:
                with STATE_LOCK:
                    STATE["running"] = False
                    STATE["status"] = str(exc)
                    STATE["log"] = traceback.format_exc()
                    STATE["result"] = None
                _json_response(self, {"error": str(exc)}, 400)
                return
            thread = threading.Thread(target=_run_job, args=(form,), daemon=True)
            thread.start()
            _json_response(self, {"ok": True})
            return
        _json_response(self, {"error": "not found"}, 404)

    def _serve_index(self) -> None:
        """Render and send the localized single-page web UI.

        Template values are derived from the module-level language setting.
        """
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
            "__TOOL__": html.escape(t("tool", LANG)),
            "__WIKI__": html.escape(t("wiki", LANG)),
            "__CHOOSE_FILE__": html.escape(t("choose_file", LANG)),
            "__CHOOSE_DIRECTORY__": html.escape(t("choose_directory", LANG)),
            "__MANUAL_PATH__": html.escape(t("manual_path", LANG)),
            "__NO_FILE_SELECTED__": html.escape(t("no_file_selected", LANG)),
            "__SELECTED_FILE_TEMPLATE__": html.escape(t("selected_file", LANG, name="{name}")),
            "__SELECTED_FILES_TEMPLATE__": html.escape(t("selected_files", LANG, count="{count}")),
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

    def _serve_wiki(self, slug: str) -> None:
        """Render and send a localized wiki page.

        Args:
            slug: Wiki slug extracted from the request path.
        """
        wiki_file = _wiki_file_for_slug(slug)
        if wiki_file is None or not wiki_file.exists():
            _json_response(self, {"error": t("wiki_not_found", LANG)}, 404)
            return

        markdown = wiki_file.read_text(encoding="utf-8")
        body_html = _render_markdown(markdown)
        title = next(
            (en if LANG == "en" else ko for page_slug, ko, en in WIKI_PAGES if page_slug == _wiki_base_slug(slug)),
            t("wiki", LANG),
        )
        replacements = {
            "__VERSION__": html.escape(__version__),
            "__APP_TITLE__": html.escape(t("app_title", LANG)),
            "__LANG__": html.escape(LANG),
            "__TOOL__": html.escape(t("tool", LANG)),
            "__WIKI__": html.escape(t("wiki", LANG)),
            "__BACK_TO_TOOL__": html.escape(t("back_to_tool", LANG)),
            "__PAGE_TITLE__": html.escape(title),
            "__WIKI_NAV__": _wiki_nav_html(slug),
            "__WIKI_BODY__": body_html,
        }
        html_body = WIKI_HTML
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
    .topbar { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 18px; }
    .topbar h1 { margin: 0; }
    .topnav { display: flex; gap: 8px; }
    .topnav a {
      color: #17202a;
      text-decoration: none;
      background: #e8eef7;
      border: 1px solid #c9d4e3;
      border-radius: 6px;
      padding: 8px 12px;
      font-weight: 650;
    }
    .topnav a.active { background: #1f6feb; border-color: #1f6feb; color: white; }
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
    input[type="file"] { display: none; }
    button {
      background: #1f6feb;
      color: white;
      border-color: #1f6feb;
      cursor: pointer;
      padding: 0 16px;
    }
    button:disabled { opacity: .55; cursor: default; }
    .picker-row { display: grid; grid-template-columns: 160px 1fr; gap: 8px; align-items: center; }
    .picker-button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 36px;
      border-radius: 6px;
      border: 1px solid #b7c2d0;
      background: #e8eef7;
      color: #17202a;
      font-weight: 650;
      cursor: pointer;
      padding: 0 10px;
      box-sizing: border-box;
    }
    .selected-name { color: #52616f; font-size: 13px; overflow-wrap: anywhere; }
    details { grid-column: 2; }
    summary { cursor: pointer; color: #52616f; font-size: 13px; margin: 3px 0 6px; }
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
  <div class="topbar">
    <h1>__APP_TITLE__ __VERSION__</h1>
    <nav class="topnav" aria-label="Primary">
      <a class="active" href="/">__TOOL__</a>
      <a href="/wiki/">__WIKI__</a>
    </nav>
  </div>
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
    <form id="toolForm" enctype="multipart/form-data">
      <input type="hidden" name="mode" id="mode" value="analyze">
      <input type="hidden" name="vendor" id="vendorField" value="ASUS">
      <div id="analyzeFields" class="grid">
        <label for="analyze_file">__BIOS_SECTION_FILE__</label>
        <div class="picker-row">
          <label class="picker-button" for="analyze_file_upload">__CHOOSE_FILE__</label>
          <span class="selected-name" data-for="analyze_file_upload">__NO_FILE_SELECTED__</span>
        </div>
        <input id="analyze_file_upload" name="analyze_file_upload" type="file">
        <details>
          <summary>__MANUAL_PATH__</summary>
          <input id="analyze_file" name="analyze_file" placeholder="__PATH_FILE_PLACEHOLDER__">
        </details>
      </div>
      <div id="repackFields" class="grid hidden">
        <label for="original_file">__ORIGINAL_BIOS_FILE__</label>
        <div class="picker-row">
          <label class="picker-button" for="original_file_upload">__CHOOSE_FILE__</label>
          <span class="selected-name" data-for="original_file_upload">__NO_FILE_SELECTED__</span>
        </div>
        <input id="original_file_upload" name="original_file_upload" type="file">
        <details>
          <summary>__MANUAL_PATH__</summary>
          <input id="original_file" name="original_file" placeholder="__PATH_ORIGINAL_PLACEHOLDER__">
        </details>
        <label for="input_dir">__EXTRACTED_IMAGE_DIR__</label>
        <div class="picker-row">
          <label class="picker-button" for="input_dir_upload">__CHOOSE_DIRECTORY__</label>
          <span class="selected-name" data-for="input_dir_upload">__NO_FILE_SELECTED__</span>
        </div>
        <input id="input_dir_upload" name="input_dir_upload" type="file" webkitdirectory multiple>
        <details>
          <summary>__MANUAL_PATH__</summary>
          <input id="input_dir" name="input_dir" placeholder="__PATH_DIR_PLACEHOLDER__">
        </details>
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
const noFileSelected = '__NO_FILE_SELECTED__';
const selectedFileTemplate = '__SELECTED_FILE_TEMPLATE__';
const selectedFilesTemplate = '__SELECTED_FILES_TEMPLATE__';

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

function updateSelectedName(input) {
  const label = document.querySelector(`[data-for="${input.id}"]`);
  if (!label) return;
  if (!input.files || input.files.length === 0) {
    label.textContent = noFileSelected;
  } else if (input.files.length === 1) {
    label.textContent = selectedFileTemplate.replace('{name}', input.files[0].name);
  } else {
    label.textContent = selectedFilesTemplate.replace('{count}', input.files.length);
  }
}
document.querySelectorAll('input[type="file"]').forEach((input) => {
  input.addEventListener('change', () => updateSelectedName(input));
});

form.onsubmit = async (event) => {
  event.preventDefault();
  vendorField.value = vendor.value;
  runButton.disabled = true;
  logEl.textContent = '';
  const formData = new FormData(form);
  const response = await fetch('/api/run', {
    method: 'POST',
    body: formData
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


WIKI_HTML = """<!doctype html>
<html lang="__LANG__">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>__PAGE_TITLE__ - __APP_TITLE__ __VERSION__</title>
  <style>
    :root {
      color-scheme: light;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f5f7fa;
      color: #17202a;
    }
    body { margin: 0; }
    main { max-width: 1120px; margin: 0 auto; padding: 24px; }
    .topbar { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 18px; }
    h1 { font-size: 24px; margin: 0; }
    h2 { font-size: 20px; margin: 28px 0 10px; }
    h3 { font-size: 17px; margin: 22px 0 8px; }
    p, li, blockquote, td, th { line-height: 1.55; }
    .topnav, .wiki-layout nav { display: flex; gap: 8px; }
    .topnav a, .wiki-layout nav a {
      color: #17202a;
      text-decoration: none;
      background: #e8eef7;
      border: 1px solid #c9d4e3;
      border-radius: 6px;
      padding: 8px 12px;
      font-weight: 650;
    }
    .topnav a.active, .wiki-layout nav a.active {
      background: #1f6feb;
      border-color: #1f6feb;
      color: white;
    }
    .wiki-layout { display: grid; grid-template-columns: 240px minmax(0, 1fr); gap: 18px; align-items: start; }
    .wiki-layout nav { flex-direction: column; position: sticky; top: 24px; }
    article {
      background: white;
      border: 1px solid #d7dee8;
      border-radius: 8px;
      padding: 20px 24px;
      overflow: auto;
    }
    article h1 { margin-bottom: 18px; }
    code {
      background: #eef2f7;
      border-radius: 4px;
      padding: 1px 4px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: .94em;
    }
    pre {
      overflow: auto;
      background: #111827;
      color: #e5e7eb;
      border-radius: 8px;
      padding: 12px;
      line-height: 1.45;
    }
    pre code { background: transparent; color: inherit; padding: 0; }
    blockquote {
      margin: 12px 0;
      padding: 8px 12px;
      border-left: 4px solid #c9d4e3;
      background: #f8fafc;
      color: #3d4b5c;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 12px 0 18px;
      font-size: 14px;
    }
    th, td {
      border: 1px solid #d7dee8;
      padding: 8px 10px;
      text-align: left;
      vertical-align: top;
    }
    th { background: #eef2f7; }
    article a { color: #1f6feb; }
    @media (max-width: 760px) {
      .topbar { align-items: flex-start; flex-direction: column; }
      .wiki-layout { grid-template-columns: 1fr; }
      .wiki-layout nav { position: static; }
    }
  </style>
</head>
<body>
<main>
  <div class="topbar">
    <h1>__APP_TITLE__ __VERSION__</h1>
    <nav class="topnav" aria-label="Primary">
      <a href="/">__TOOL__</a>
      <a class="active" href="/wiki/">__WIKI__</a>
    </nav>
  </div>
  <div class="wiki-layout">
    <nav aria-label="Wiki pages">
      __WIKI_NAV__
    </nav>
    <article>
      __WIKI_BODY__
    </article>
  </div>
</main>
</body>
</html>
"""


def _find_free_port() -> int:
    """Ask the OS for an available localhost TCP port.

    Returns:
        Available TCP port bound on 127.0.0.1.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def main() -> None:
    """Launch the local browser-based fallback UI.

    The server binds to a free localhost port and opens that URL in the default browser.
    """
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
