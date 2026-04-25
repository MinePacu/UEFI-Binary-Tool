#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Small translation helper for the UI layer."""

from __future__ import annotations

import locale
import os
from typing import Any, Dict


SUPPORTED_LANGUAGES = ("ko", "en")


TRANSLATIONS: Dict[str, Dict[str, str]] = {
    "ko": {
        "app_title": "UEFI Binary Tool",
        "ready": "대기 중",
        "vendor": "제조사",
        "ui_intro": "분석과 리패킹은 기존 로직을 사용하며 작업 로그가 아래에 표시됩니다.",
        "work_log": "작업 로그",
        "analyze": "분석",
        "repack": "리패킹",
        "bios_section_file": "BIOS/Section 파일",
        "browse": "찾기",
        "start_analyze": "분석 시작",
        "original_bios_file": "원본 BIOS 파일",
        "extracted_image_dir": "추출 이미지 디렉터리",
        "output_file": "출력 파일",
        "save_location": "저장 위치",
        "start_repack": "리패킹 시작",
        "msi_repack_hint": "MSI 원본 BIOS 파일은 선택 사항입니다. 지정하면 원본 분석 결과를 사용해 구조 보존을 강화합니다.",
        "asus_repack_hint": "ASUS 리패킹은 원본 BIOS 파일과 asus_extracted/asus_pack_* 디렉터리 구조가 필요합니다.",
        "choose_analyze_file": "분석할 파일 선택",
        "choose_original_file": "원본 BIOS 파일 선택",
        "choose_extracted_dir": "추출 이미지 디렉터리 선택",
        "choose_output_file": "출력 파일 선택",
        "busy_title": "작업 진행 중",
        "busy_message": "현재 작업이 끝난 뒤 다시 실행하세요.",
        "operation_running": "{label} 실행 중",
        "completed_title": "완료",
        "failed_title": "실패",
        "start": "시작",
        "result": "결과",
        "outputs": "출력",
        "analyze_label": "{vendor} 분석",
        "repack_label": "{vendor} 리패킹",
        "browser_path_hint": "파일 선택 창은 브라우저 보안상 로컬 경로를 앱에 전달하지 않으므로 전체 경로를 입력하세요.",
        "path_file_placeholder": "/path/to/file.bin",
        "path_original_placeholder": "/path/to/original.bin",
        "path_dir_placeholder": "/path/to/asus_extracted 또는 /path/to/msi_extracted",
        "auto_output_placeholder": "비워두면 자동 생성",
        "run_failed": "실행 실패",
        "already_running": "작업이 이미 실행 중입니다.",
        "job_running": "작업 실행 중",
        "server_url": "UEFI Binary Tool 웹 UI: {url}",
        "server_stopped": "서버를 종료합니다.",
        "path_empty": "{label} 경로가 비어 있습니다.",
        "file_not_found": "{label}을 찾을 수 없습니다: {path}",
        "dir_not_found": "{label}를 찾을 수 없습니다: {path}",
        "file_label": "파일",
        "dir_label": "디렉터리",
        "asus_bios_file": "ASUS BIOS 파일",
        "msi_bios_file": "MSI BIOS 파일",
        "asus_original_bios_file": "ASUS 원본 BIOS 파일",
        "msi_original_bios_file": "MSI 원본 BIOS 파일",
        "asus_extracted_dir": "ASUS 추출 디렉터리",
        "msi_extracted_dir": "MSI 추출 디렉터리",
        "gui_summary_failed": "[WARNING] GUI 요약 데이터 생성 실패: {error}",
        "asus_analyze_done": "ASUS 분석이 완료되었습니다.",
        "msi_analyze_failed": "MSI 분석에 실패했습니다.",
        "msi_analyze_done": "MSI 분석이 완료되었습니다. 엔트리 {entries}개를 확인했습니다.",
        "asus_repack_done": "ASUS 리패킹이 완료되었습니다.",
        "asus_repack_failed": "ASUS 리패킹에 실패했습니다.",
        "msi_repack_done": "MSI 리패킹이 완료되었습니다.",
        "msi_repack_failed": "MSI 리패킹에 실패했습니다.",
        "language": "언어",
        "language_name": "한국어",
    },
    "en": {
        "app_title": "UEFI Binary Tool",
        "ready": "Ready",
        "vendor": "Vendor",
        "ui_intro": "Analysis and repacking use the existing engine. Progress is shown in the log below.",
        "work_log": "Operation Log",
        "analyze": "Analyze",
        "repack": "Repack",
        "bios_section_file": "BIOS/Section file",
        "browse": "Browse",
        "start_analyze": "Start Analysis",
        "original_bios_file": "Original BIOS file",
        "extracted_image_dir": "Extracted image directory",
        "output_file": "Output file",
        "save_location": "Save As",
        "start_repack": "Start Repack",
        "msi_repack_hint": "The MSI original BIOS file is optional. Providing it strengthens structure preservation with original analysis data.",
        "asus_repack_hint": "ASUS repacking requires the original BIOS file and an asus_extracted/asus_pack_* directory structure.",
        "choose_analyze_file": "Choose file to analyze",
        "choose_original_file": "Choose original BIOS file",
        "choose_extracted_dir": "Choose extracted image directory",
        "choose_output_file": "Choose output file",
        "busy_title": "Operation in progress",
        "busy_message": "Run another operation after the current one finishes.",
        "operation_running": "{label} running",
        "completed_title": "Completed",
        "failed_title": "Failed",
        "start": "Start",
        "result": "Result",
        "outputs": "Outputs",
        "analyze_label": "{vendor} Analysis",
        "repack_label": "{vendor} Repack",
        "browser_path_hint": "Because of browser security restrictions, enter full local paths instead of using a file picker.",
        "path_file_placeholder": "/path/to/file.bin",
        "path_original_placeholder": "/path/to/original.bin",
        "path_dir_placeholder": "/path/to/asus_extracted or /path/to/msi_extracted",
        "auto_output_placeholder": "Leave empty to auto-generate",
        "run_failed": "Run failed",
        "already_running": "An operation is already running.",
        "job_running": "Operation running",
        "server_url": "UEFI Binary Tool web UI: {url}",
        "server_stopped": "Server stopped.",
        "path_empty": "{label} path is empty.",
        "file_not_found": "{label} not found: {path}",
        "dir_not_found": "{label} not found: {path}",
        "file_label": "File",
        "dir_label": "Directory",
        "asus_bios_file": "ASUS BIOS file",
        "msi_bios_file": "MSI BIOS file",
        "asus_original_bios_file": "ASUS original BIOS file",
        "msi_original_bios_file": "MSI original BIOS file",
        "asus_extracted_dir": "ASUS extracted directory",
        "msi_extracted_dir": "MSI extracted directory",
        "gui_summary_failed": "[WARNING] Failed to build GUI summary data: {error}",
        "asus_analyze_done": "ASUS analysis completed.",
        "msi_analyze_failed": "MSI analysis failed.",
        "msi_analyze_done": "MSI analysis completed. Found {entries} entries.",
        "asus_repack_done": "ASUS repack completed.",
        "asus_repack_failed": "ASUS repack failed.",
        "msi_repack_done": "MSI repack completed.",
        "msi_repack_failed": "MSI repack failed.",
        "language": "Language",
        "language_name": "English",
    },
}


def detect_language() -> str:
    """Return the UI language from the OS locale.

    UEFI_BINARY_TOOL_LANG can be set to "ko" or "en" for testing or packaging.
    """
    override = os.environ.get("UEFI_BINARY_TOOL_LANG", "").strip().lower()
    if override in SUPPORTED_LANGUAGES:
        return override

    locale_name = ""
    try:
        locale_name = locale.getlocale()[0] or ""
    except Exception:
        locale_name = ""

    if not locale_name:
        try:
            locale_name = locale.getdefaultlocale()[0] or ""
        except Exception:
            locale_name = ""

    return "ko" if locale_name.lower().startswith("ko") else "en"


def t(key: str, lang: str | None = None, **kwargs: Any) -> str:
    """Translate a message key for the selected language and format placeholders."""
    language = lang or detect_language()
    text = TRANSLATIONS.get(language, TRANSLATIONS["en"]).get(key)
    if text is None:
        text = TRANSLATIONS["en"].get(key, key)
    return text.format(**kwargs) if kwargs else text
