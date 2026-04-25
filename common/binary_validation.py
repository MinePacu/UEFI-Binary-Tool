#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Binary format validation helpers for ASUS/MSI packer files."""

from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass, field
from typing import List, Optional


MSI_SIGNATURE = b"$MsI$"
MSI_HEADER_SIZE = len(MSI_SIGNATURE) + 8

ASUS_PACKER_PATTERN = re.compile(
    br"\x00\x00\x00\x00\x20\x00\x00\x00\xFF\xFF\x00\x00\xFF\xFF\x00\x00"
    br"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
)


@dataclass
class ValidationResult:
    """Result object returned by ASUS/MSI binary validation helpers."""

    is_valid: bool
    message: str
    details: List[str] = field(default_factory=list)


def _read_file(file_path: str) -> tuple[Optional[bytes], ValidationResult]:
    """Read a binary file and return basic file-system validation results."""
    if not file_path:
        return None, ValidationResult(False, "파일 경로가 비어 있습니다.")

    if not os.path.exists(file_path):
        return None, ValidationResult(False, f"파일을 찾을 수 없습니다: {file_path}")

    if not os.path.isfile(file_path):
        return None, ValidationResult(False, f"지정된 경로가 파일이 아닙니다: {file_path}")

    if os.path.getsize(file_path) < MSI_HEADER_SIZE:
        return None, ValidationResult(False, "파일이 너무 작아 지원 형식으로 볼 수 없습니다.")

    try:
        with open(file_path, "rb") as file:
            data = file.read()
    except OSError as exc:
        return None, ValidationResult(False, f"파일을 읽을 수 없습니다: {exc}")

    if not data:
        return None, ValidationResult(False, "빈 파일입니다.")

    return data, ValidationResult(True, "기본 파일 검증 통과")


def validate_msi_binary(file_path: str) -> ValidationResult:
    """Validate that a file contains at least one plausible MSI Packer entry."""
    data, basic = _read_file(file_path)
    if not basic.is_valid or data is None:
        return basic

    signature_offsets = []
    valid_entries = []
    offset = 0

    while True:
        pos = data.find(MSI_SIGNATURE, offset)
        if pos == -1:
            break
        signature_offsets.append(pos)
        if pos + MSI_HEADER_SIZE <= len(data):
            size_offset = pos + len(MSI_SIGNATURE) + 4
            image_size = struct.unpack("<I", data[size_offset : size_offset + 4])[0]
            image_start = pos + MSI_HEADER_SIZE
            image_end = image_start + image_size
            if image_size > 0 and image_end <= len(data):
                valid_entries.append((pos, image_size))
        offset = pos + 1

    if not signature_offsets:
        return ValidationResult(
            False,
            "MSI Packer 시그니처 '$MsI$'를 찾을 수 없습니다.",
            ["MSI Click BIOS X Section Binary 파일인지 확인하세요."],
        )

    if not valid_entries:
        return ValidationResult(
            False,
            "MSI Packer 시그니처는 있지만 유효한 엔트리 구조를 찾을 수 없습니다.",
            [
                f"시그니처 발견 수: {len(signature_offsets)}",
                "헤더의 이미지 크기 필드가 파일 범위를 벗어났을 수 있습니다.",
            ],
        )

    return ValidationResult(
        True,
        "유효한 MSI Packer 파일입니다.",
        [
            f"시그니처 발견 수: {len(signature_offsets)}",
            f"유효 엔트리 수: {len(valid_entries)}",
        ],
    )


def validate_asus_binary(file_path: str) -> ValidationResult:
    """Validate that a file contains a plausible ASUS Packer package."""
    data, basic = _read_file(file_path)
    if not basic.is_valid or data is None:
        return basic

    packages = []
    position = 0
    while True:
        match = ASUS_PACKER_PATTERN.search(data, position)
        if match is None:
            break

        header_end = match.end()
        if _has_plausible_asus_image_metadata(data, header_end):
            packages.append(match.start())
        position = match.end()

    if not packages:
        return ValidationResult(
            False,
            "ASUS Packer 패키지 구조를 찾을 수 없습니다.",
            ["ASUS Packer로 추출/리패킹 가능한 Section Binary 파일인지 확인하세요."],
        )

    return ValidationResult(
        True,
        "유효한 ASUS Packer 파일입니다.",
        [f"ASUS Packer 패키지 수: {len(packages)}"],
    )


def _has_plausible_asus_image_metadata(data: bytes, metadata_offset: int) -> bool:
    """Return whether ASUS image metadata at the given offset is structurally plausible."""
    if metadata_offset + 8 > len(data):
        return False

    image_size = struct.unpack("<I", data[metadata_offset : metadata_offset + 4])[0]
    image_offset = struct.unpack("<I", data[metadata_offset + 4 : metadata_offset + 8])[0]

    if image_size <= 0 or image_offset <= 0:
        return False

    image_start = metadata_offset + image_offset
    image_end = image_start + image_size
    if image_end > len(data):
        return False

    if metadata_offset + image_offset - 0x10 >= 0:
        check_offset = metadata_offset + image_offset - 0x10
        expected = bytes.fromhex("00000000300009040000000000000000")
        if check_offset + len(expected) <= len(data) and data[check_offset : check_offset + len(expected)] != expected:
            return False

    return True


def validate_vendor_binary(file_path: str, vendor: str) -> ValidationResult:
    """Validate a binary file using the vendor-specific ASUS or MSI validator."""
    vendor_name = vendor.strip().lower()
    if vendor_name == "asus":
        return validate_asus_binary(file_path)
    if vendor_name == "msi":
        return validate_msi_binary(file_path)
    return ValidationResult(False, f"지원하지 않는 제조사입니다: {vendor}")


def require_valid_vendor_binary(file_path: str, vendor: str) -> ValidationResult:
    """Validate a vendor binary and raise ValueError when it is invalid."""
    result = validate_vendor_binary(file_path, vendor)
    if not result.is_valid:
        detail = "\n".join(f"- {item}" for item in result.details)
        suffix = f"\n{detail}" if detail else ""
        raise ValueError(f"{result.message}{suffix}")
    return result
