#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reusable operations for the GUI layer.

The existing analyzer and repacker modules are intentionally kept as-is so the
batch files and command-line workflows continue to work. This module provides a
small, UI-friendly boundary around them.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from common.binary_validation import require_valid_vendor_binary
from asus.analyzer.asus_analyzer import AsusFileAnalyzer
from asus.repacker.asus_repacker import (
    AsusImageRepacker,
    localize_asus_validation_detail,
    localize_asus_validation_error,
)
from msi.analyzer.msi_analyzer import MSIFileAnalyzer
from msi.repacker.msi_repacker import (
    MSIImageRepacker,
    localize_msi_validation_detail,
    localize_msi_validation_error,
)
from uefi_binary_tool.i18n import t


@dataclass
class OperationResult:
    """UI-friendly result object for analysis and repack operations."""

    success: bool
    message: str
    outputs: List[str] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)


def _require_file(file_path: str, label: str = "") -> None:
    """Validate that file_path points to an existing file."""
    label = label or t("file_label")
    if not file_path:
        raise ValueError(t("path_empty", label=label))
    if not os.path.isfile(file_path):
        raise FileNotFoundError(t("file_not_found", label=label, path=file_path))


def _require_dir(dir_path: str, label: str = "") -> None:
    """Validate that dir_path points to an existing directory."""
    label = label or t("dir_label")
    if not dir_path:
        raise ValueError(t("path_empty", label=label))
    if not os.path.isdir(dir_path):
        raise FileNotFoundError(t("dir_not_found", label=label, path=dir_path))


def default_analysis_report_path(file_path: str, vendor: str) -> str:
    """Return the default report path for an analysis operation."""
    base = os.path.splitext(file_path)[0]
    if vendor.lower() == "asus":
        return f"{base}_analysis.txt"
    return f"{base}_{vendor.lower()}_analysis_report.txt"


def default_repack_output_path(input_path: str, vendor: str) -> str:
    """Return the default output path for a repack operation."""
    base = os.path.splitext(input_path)[0] if os.path.isfile(input_path) else input_path
    return f"{base}_{vendor.lower()}_repacked.bin"


def analyze_asus(file_path: str) -> OperationResult:
    """Validate and analyze an ASUS BIOS/Section binary file."""
    _require_file(file_path, t("asus_bios_file"))
    validation = require_valid_vendor_binary(file_path, "asus")
    for detail in validation.details:
        print(f"[VALID] {detail}")

    analyzer = AsusFileAnalyzer(file_path)
    analyzer.run_full_analysis()

    base = os.path.splitext(file_path)[0]
    outputs = [f"{base}_analysis.txt", f"{base}_analysis.md"]
    outputs = [path for path in outputs if os.path.exists(path)]

    data: Dict[str, Any] = {}
    try:
        data = analyzer.collect_analysis_data()
    except Exception as exc:
        print(t("gui_summary_failed", error=exc))

    return OperationResult(
        success=True,
        message=t("asus_analyze_done"),
        outputs=outputs,
        data=data,
    )


def analyze_msi(file_path: str) -> OperationResult:
    """Validate and analyze an MSI BIOS/Section binary file."""
    _require_file(file_path, t("msi_bios_file"))
    validation = require_valid_vendor_binary(file_path, "msi")
    for detail in validation.details:
        print(f"[VALID] {detail}")

    analyzer = MSIFileAnalyzer()
    data = analyzer.analyze_file(file_path)
    if not data:
        return OperationResult(False, t("msi_analyze_failed"))

    report_path = default_analysis_report_path(file_path, "msi")
    analyzer.export_analysis_report(report_path)

    outputs = [report_path] if os.path.exists(report_path) else []
    entries = data.get("summary", {}).get("total_entries", 0)
    return OperationResult(
        success=True,
        message=t("msi_analyze_done", entries=entries),
        outputs=outputs,
        data=data,
    )


def repack_asus(
    original_file: str,
    extracted_dir: str,
    output_file: str = "",
    log: Optional[Callable[[str], None]] = None,
    lang: Optional[str] = None,
) -> OperationResult:
    """Repack ASUS extracted images using the original binary as structure source."""
    _require_file(original_file, t("asus_original_bios_file"))
    try:
        validation = require_valid_vendor_binary(original_file, "asus")
    except ValueError as exc:
        raise ValueError(localize_asus_validation_error(str(exc), lang)) from exc
    for detail in validation.details:
        localized_detail = localize_asus_validation_detail(detail, lang)
        if log:
            log(f"[VALID] {localized_detail}\n")
        else:
            print(f"[VALID] {localized_detail}")
    _require_dir(extracted_dir, t("asus_extracted_dir"))

    output_file = output_file or default_repack_output_path(original_file, "asus")
    repacker = AsusImageRepacker(original_file, log=log, lang=lang)
    success = repacker.run_repack(extracted_dir, output_file)

    return OperationResult(
        success=success,
        message=t("asus_repack_done") if success else t("asus_repack_failed"),
        outputs=[output_file] if success and os.path.exists(output_file) else [],
    )


def repack_msi(
    input_dir: str,
    output_file: str = "",
    original_file: Optional[str] = None,
    log: Optional[Callable[[str], None]] = None,
    lang: Optional[str] = None,
) -> OperationResult:
    """Repack MSI extracted images, optionally using an original binary for validation."""
    _require_dir(input_dir, t("msi_extracted_dir"))
    if original_file:
        _require_file(original_file, t("msi_original_bios_file"))
        try:
            validation = require_valid_vendor_binary(original_file, "msi")
        except ValueError as exc:
            raise ValueError(localize_msi_validation_error(str(exc), lang)) from exc
        for detail in validation.details:
            localized_detail = localize_msi_validation_detail(detail, lang)
            if log:
                log(f"[VALID] {localized_detail}\n")
            else:
                print(f"[VALID] {localized_detail}")

    output_file = output_file or default_repack_output_path(input_dir, "msi")
    analyzer = MSIFileAnalyzer()
    original_analysis = analyzer.analyze_file(original_file) if original_file else None

    repacker = MSIImageRepacker(log=log, lang=lang)
    success = repacker.repack_from_directory(
        input_dir,
        output_file,
        preserve_order=True,
        original_analysis=original_analysis,
        original_file=original_file,
    )

    outputs: List[str] = []
    if success and os.path.exists(output_file):
        outputs.append(output_file)
        report_path = f"{os.path.splitext(output_file)[0]}_repack_report.txt"
        if repacker.export_repack_report(report_path) and os.path.exists(report_path):
            outputs.append(report_path)

    return OperationResult(
        success=success,
        message=t("msi_repack_done") if success else t("msi_repack_failed"),
        outputs=outputs,
        data=repacker.repack_results,
    )
