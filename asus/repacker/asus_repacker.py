#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ASUS image repacker
Repackages extracted images back into ASUS Packer format.
"""

import os
import re
import binascii
import struct
from typing import Callable, Optional

from common.binary_validation import require_valid_vendor_binary
from uefi_binary_tool.i18n import detect_language


REPACKER_TEXT = {
    "ko": {
        "original_loaded": "원본 파일 로드 완료: {path}",
        "file_size": "파일 크기: {size:,} bytes ({mb:.2f} MB)",
        "detect_title": "\n=== ASUS Packer 형식 감지 ===",
        "package_found": "ASUS Packer 패키지 발견: 오프셋 0x{offset:08x}",
        "image_found": "  이미지 #{number}: {image_type}, 크기={size}, 오프셋=0x{offset:08x}",
        "package_done": "패키지 완료: {image_count}개 이미지, 총 크기={total_size} bytes\n",
        "packages_total": "총 {count}개의 ASUS Packer 패키지 발견",
        "packages_not_found": "ASUS Packer 패키지를 찾을 수 없습니다.",
        "image_type_changed": "  ⚠️ 경고: 이미지 형식 변경 감지 ({original_type} → {new_type})",
        "repack_title": "\n=== ASUS Packer 원본 구조 보존 재패키징 ===",
        "extracted_dir_missing": "오류: 추출된 파일 디렉터리를 찾을 수 없습니다 - {path}",
        "step_analyze": "1단계: 원본 ASUS 패키지 구조 분석...",
        "original_package_missing": "오류: 원본 파일에서 ASUS 패키지를 찾을 수 없습니다.",
        "step_detect_modified": "2단계: 수정된 이미지 파일 감지...",
        "package_dir_missing": "  경고: 패키지 {pkg_idx} 디렉터리가 없습니다: {path}",
        "bad_filename_pattern": "  [WARNING] 생성된 파일명 패턴이 올바르지 않음 (image_nr{{숫자}}_off0x{{16진수}}.{{확장자}} 형식이어야 함): {filename}",
        "skip_type_mismatch_file": "  ❌ 형식 불일치로 건너뛰기: {filename}",
        "unchanged_image": "  변경없음: 이미지 #{number} ({size} bytes)",
        "modified_image": "  🔄 수정됨: 이미지 #{number} ({old_size} → {new_size} bytes, {diff:+} bytes)",
        "extracted_file_missing": "  경고: 추출된 파일을 찾을 수 없습니다: {filename}",
        "change_summary": "\n변경 요약:",
        "summary_total": "  📋 총 이미지: {count}개",
        "summary_unchanged": "  ✅ 변경없음: {count}개",
        "summary_modified": "  🔄 수정됨: {count}개",
        "no_modified_copy": "수정된 이미지가 없으므로 원본 파일을 그대로 복사합니다.",
        "copy_done": "원본 파일 복사 완료: {path}",
        "copy_failed": "파일 복사 실패: {error}",
        "step_size_change": "3단계: 크기 변화 분석...",
        "total_size_no_change": "  📊 총 크기 변화: {change} bytes (변화 없음)",
        "total_size_change": "  📊 총 크기 변화: {change:+} bytes",
        "method_direct": "  🔧 처리 방식: 바이트 단위 직접 교체",
        "method_rebuild": "  🔧 처리 방식: 구조 보존 재구성",
        "step_direct": "\n4단계: 바이트 단위 직접 교체...",
        "skip_size_mismatch_offset": "  ❌ 크기 불일치로 건너뛰기: 오프셋 0x{offset:08x}",
        "skip_type_mismatch_offset": "  ❌ 형식 불일치로 건너뛰기: 오프셋 0x{offset:08x}",
        "replace_done": "  ✅ 교체 완료: 오프셋 0x{offset:08x}, 이미지 #{number}, {size} bytes",
        "direct_done": "\n✅ 바이트 단위 교체 완료:",
        "replaced_images": "  🔄 교체된 이미지: {count}개",
        "file_size_no_change": "  📏 파일 크기: {size:,} bytes (변화 없음)",
        "output_file": "  📁 출력 파일: {path}",
        "structure_100": "  🎯 구조 보존: 100% (원본과 동일)",
        "image_validation_done": "  ✅ 이미지 형식 검증: 완료",
        "save_failed": "❌ 파일 저장 실패: {error}",
        "step_rebuild": "\n4단계: 원본 ASUS 구조 완전 복원...",
        "processing_package": "\n  📦 패키지 {pkg_idx} 처리 중...",
        "preserve_before_package": "    📋 패키지 전 데이터 보존: {size} bytes",
        "preserve_header": "    🏷️ ASUS 헤더 보존: {size} bytes",
        "replace_image": "      🔄 교체: 이미지 #{number} ({old_size} → {new_size} bytes)",
        "preserve_image": "      ✅ 보존: 이미지 #{number} ({size} bytes)",
        "preserve_special": "        🔧 원본 특별 패턴 보존: 24 bytes",
        "extract_special": "        🔧 원본 특별 패턴 추출 보존: 24 bytes",
        "default_special": "        ⚠️ 기본 특별 패턴 사용: 24 bytes",
        "add_padding": "        🔧 패딩 추가: {padding} bytes (4바이트 정렬)",
        "package_complete": "    📊 패키지 {pkg_idx} 완료:",
        "package_replaced": "      - 교체된 이미지: {count}개",
        "package_total": "      - 총 이미지: {count}개",
        "package_special_preserved": "      - 원본 특별 패턴 보존: ✅",
        "package_structure": "      - 구조 복원: 메타데이터+원본패턴+이미지 인터리브",
        "preserve_after_package": "\n  📋 패키지 후 데이터 보존: {size} bytes",
        "rebuild_done": "\n✅ 구조 보존 재구성 완료:",
        "original_size": "  📏 원본 크기: {size:,} bytes",
        "final_size": "  📏 최종 크기: {size:,} bytes",
        "size_diff": "  📊 크기 변화: {diff:+,} bytes",
        "structure_max": "  🎯 구조 보존: 최대화 (헤더, 원본 특별패턴, 순서, 패딩 모두 보존)",
        "start": "ASUS 이미지 리패킹을 시작합니다...",
        "success": "[SUCCESS] ASUS 이미지 리패킹이 완료되었습니다!",
        "failed": "[ERROR] ASUS 이미지 리패킹이 실패했습니다.",
    },
    "en": {
        "original_loaded": "Original file loaded: {path}",
        "file_size": "File size: {size:,} bytes ({mb:.2f} MB)",
        "detect_title": "\n=== Detecting ASUS Packer Format ===",
        "package_found": "ASUS Packer package found: offset 0x{offset:08x}",
        "image_found": "  Image #{number}: {image_type}, size={size}, offset=0x{offset:08x}",
        "package_done": "Package complete: {image_count} images, total size={total_size} bytes\n",
        "packages_total": "Found {count} ASUS Packer package(s)",
        "packages_not_found": "No ASUS Packer package found.",
        "image_type_changed": "  ⚠️ Warning: image type change detected ({original_type} → {new_type})",
        "repack_title": "\n=== ASUS Packer Structure-Preserving Repack ===",
        "extracted_dir_missing": "Error: extracted file directory not found - {path}",
        "step_analyze": "Step 1: Analyzing original ASUS package structure...",
        "original_package_missing": "Error: no ASUS package found in the original file.",
        "step_detect_modified": "Step 2: Detecting modified image files...",
        "package_dir_missing": "  Warning: package {pkg_idx} directory is missing: {path}",
        "bad_filename_pattern": "  [WARNING] Generated filename pattern is invalid (expected image_nr{{number}}_off0x{{hex}}.{{ext}}): {filename}",
        "skip_type_mismatch_file": "  ❌ Skipped due to type mismatch: {filename}",
        "unchanged_image": "  Unchanged: image #{number} ({size} bytes)",
        "modified_image": "  🔄 Modified: image #{number} ({old_size} → {new_size} bytes, {diff:+} bytes)",
        "extracted_file_missing": "  Warning: extracted file not found: {filename}",
        "change_summary": "\nChange summary:",
        "summary_total": "  📋 Total images: {count}",
        "summary_unchanged": "  ✅ Unchanged: {count}",
        "summary_modified": "  🔄 Modified: {count}",
        "no_modified_copy": "No modified images found; copying the original file unchanged.",
        "copy_done": "Original file copied: {path}",
        "copy_failed": "File copy failed: {error}",
        "step_size_change": "Step 3: Analyzing size changes...",
        "total_size_no_change": "  📊 Total size change: {change} bytes (no change)",
        "total_size_change": "  📊 Total size change: {change:+} bytes",
        "method_direct": "  🔧 Method: direct byte replacement",
        "method_rebuild": "  🔧 Method: structure-preserving rebuild",
        "step_direct": "\nStep 4: Direct byte replacement...",
        "skip_size_mismatch_offset": "  ❌ Skipped due to size mismatch: offset 0x{offset:08x}",
        "skip_type_mismatch_offset": "  ❌ Skipped due to type mismatch: offset 0x{offset:08x}",
        "replace_done": "  ✅ Replacement complete: offset 0x{offset:08x}, image #{number}, {size} bytes",
        "direct_done": "\n✅ Direct byte replacement complete:",
        "replaced_images": "  🔄 Replaced images: {count}",
        "file_size_no_change": "  📏 File size: {size:,} bytes (no change)",
        "output_file": "  📁 Output file: {path}",
        "structure_100": "  🎯 Structure preservation: 100% (same as original)",
        "image_validation_done": "  ✅ Image type validation: complete",
        "save_failed": "❌ Failed to save file: {error}",
        "step_rebuild": "\nStep 4: Rebuilding original ASUS structure...",
        "processing_package": "\n  📦 Processing package {pkg_idx}...",
        "preserve_before_package": "    📋 Preserved data before package: {size} bytes",
        "preserve_header": "    🏷️ Preserved ASUS header: {size} bytes",
        "replace_image": "      🔄 Replace: image #{number} ({old_size} → {new_size} bytes)",
        "preserve_image": "      ✅ Preserve: image #{number} ({size} bytes)",
        "preserve_special": "        🔧 Preserved original special pattern: 24 bytes",
        "extract_special": "        🔧 Extracted and preserved original special pattern: 24 bytes",
        "default_special": "        ⚠️ Using default special pattern: 24 bytes",
        "add_padding": "        🔧 Added padding: {padding} bytes (4-byte alignment)",
        "package_complete": "    📊 Package {pkg_idx} complete:",
        "package_replaced": "      - Replaced images: {count}",
        "package_total": "      - Total images: {count}",
        "package_special_preserved": "      - Original special pattern preserved: ✅",
        "package_structure": "      - Structure rebuilt: metadata + original pattern + image interleaving",
        "preserve_after_package": "\n  📋 Preserved data after package: {size} bytes",
        "rebuild_done": "\n✅ Structure-preserving rebuild complete:",
        "original_size": "  📏 Original size: {size:,} bytes",
        "final_size": "  📏 Final size: {size:,} bytes",
        "size_diff": "  📊 Size change: {diff:+,} bytes",
        "structure_max": "  🎯 Structure preservation: maximized (header, original special patterns, order, and padding preserved)",
        "start": "Starting ASUS image repack...",
        "success": "[SUCCESS] ASUS image repack completed!",
        "failed": "[ERROR] ASUS image repack failed.",
    },
}


def localize_asus_validation_detail(detail: str, lang: Optional[str] = None) -> str:
    """Localize ASUS validation details returned by the shared binary validator."""
    language = (lang or detect_language()).lower()
    if language.startswith("ko"):
        return detail

    match = re.fullmatch(r"ASUS Packer 패키지 수: (\d+)", detail)
    if match:
        return f"ASUS Packer package count: {match.group(1)}"
    return detail


def localize_asus_validation_error(message: str, lang: Optional[str] = None) -> str:
    """Localize ASUS validation errors returned by the shared binary validator."""
    language = (lang or detect_language()).lower()
    if language.startswith("ko"):
        return message

    replacements = {
        "파일 경로가 비어 있습니다.": "File path is empty.",
        "파일이 너무 작아 지원 형식으로 볼 수 없습니다.": "The file is too small to be treated as a supported format.",
        "빈 파일입니다.": "The file is empty.",
        "기본 파일 검증 통과": "Basic file validation passed.",
        "ASUS Packer 패키지 구조를 찾을 수 없습니다.": "ASUS Packer package structure was not found.",
        "ASUS Packer로 추출/리패킹 가능한 Section Binary 파일인지 확인하세요.": "Check that this is a Section Binary file that can be extracted/repacked with ASUS Packer.",
    }
    localized = message
    for korean, english in replacements.items():
        localized = localized.replace(korean, english)

    localized = re.sub(r"파일을 찾을 수 없습니다: (.+)", r"File not found: \1", localized)
    localized = re.sub(r"지정된 경로가 파일이 아닙니다: (.+)", r"The specified path is not a file: \1", localized)
    localized = re.sub(r"파일을 읽을 수 없습니다: (.+)", r"Could not read file: \1", localized)
    return localized


class AsusImageRepacker:
    """Repack modified images into an ASUS Packer binary while preserving original layout data."""

    def __init__(
        self,
        file_path,
        log: Optional[Callable[[str], None]] = None,
        lang: Optional[str] = None,
    ):
        """Initialize the repacker with the original ASUS binary path."""
        self.file_path = file_path
        self.file_size = os.path.getsize(file_path)
        self.data = None
        self.log = log
        self.lang = (lang or detect_language()).lower()

    def _text(self, key, **kwargs):
        """Return a repacker log message in the configured language."""
        language = "ko" if self.lang.startswith("ko") else "en"
        template = REPACKER_TEXT[language].get(key, REPACKER_TEXT["en"][key])
        return template.format(**kwargs) if kwargs else template

    def _log(self, message=""):
        """Send repacker output to the configured UI logger or stdout."""
        text = str(message)
        if self.log:
            self.log(text + "\n")
        else:
            print(text)
        
    def load_file(self):
        """Load the file into memory."""
        try:
            validation = require_valid_vendor_binary(self.file_path, "asus")
        except ValueError as exc:
            raise ValueError(localize_asus_validation_error(str(exc), self.lang)) from exc
        for detail in validation.details:
            self._log(f"[VALID] {localize_asus_validation_detail(detail, self.lang)}")
        with open(self.file_path, 'rb') as f:
            self.data = f.read()
        self._log(self._text("original_loaded", path=self.file_path))
        self._log(self._text("file_size", size=self.file_size, mb=self.file_size / 1024 / 1024))
    
    def detect_asus_packer_format(self):
        """Detect ASUS Packer format."""
        self._log(self._text("detect_title"))
        
        # ASUS Packer signature pattern.
        asus_pattern = re.compile(br'\x00\x00\x00\x00\x20\x00\x00\x00\xFF\xFF\x00\x00\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        
        asus_packages = []
        position = 0
        
        while True:
            match = asus_pattern.search(self.data, position)
            if match is None:
                break
            
            start_match, end_match = match.span()
            self._log(self._text("package_found", offset=start_match))
            
            # Parse image metadata after the header.
            head = end_match
            images = []
            image_nr = 0
            
            while True:
                if head + 8 > len(self.data):
                    break
                    
                # Read image size and offset in little-endian format.
                isize_bytes = self.data[head:head + 4]
                ioffs_bytes = self.data[head + 4:head + 8]
                
                if len(isize_bytes) < 4 or len(ioffs_bytes) < 4:
                    break
                    
                isize = struct.unpack('<I', isize_bytes)[0]
                ioffs = struct.unpack('<I', ioffs_bytes)[0]
                
                # Validate parsed values.
                if isize == 0 or ioffs == 0:
                    break
                    
                # Check the special header pattern.
                check_offset = head + ioffs - 0x10
                if check_offset >= 0 and check_offset + 16 <= len(self.data):
                    check_pattern = self.data[check_offset:check_offset + 16]
                    expected_pattern = bytes.fromhex("00000000300009040000000000000000")
                    if check_pattern != expected_pattern:
                        break
                
                # Image data location.
                img_start = head + ioffs
                img_end = img_start + isize
                
                if img_end > len(self.data):
                    break
                    
                # Detect the image type.
                img_data = self.data[img_start:img_end]
                img_type = self.detect_asus_image_type(img_data)
                
                image_nr += 1
                # Preserve the original 24-byte special pattern.
                special_pattern_start = head + 8
                special_pattern = self.data[special_pattern_start:special_pattern_start + 24]
                
                image_info = {
                    'number': image_nr,
                    'type': img_type,
                    'size': isize,
                    'offset_in_package': ioffs,
                    'absolute_offset': img_start,
                    'data': img_data,
                    'metadata_offset': head,
                    'special_pattern_offset': special_pattern_start,
                    'special_pattern': special_pattern
                }
                images.append(image_info)
                
                self._log(self._text("image_found", number=image_nr, image_type=img_type, size=isize, offset=img_start))
                
                # Move to the next metadata block: 32-byte metadata, image data, and 4-byte alignment.
                next_metadata_pos = head + 32 + isize  # 32바이트 메타데이터 + 이미지 크기
                padding = (4 - (isize % 4)) % 4
                head = next_metadata_pos + padding
            
            package_info = {
                'header_offset': start_match,
                'header_end': end_match,
                'images': images,
                'total_size': head - start_match
            }
            asus_packages.append(package_info)
            
            position = head
            self._log(self._text("package_done", image_count=len(images), total_size=head - start_match))
        
        if asus_packages:
            self._log(self._text("packages_total", count=len(asus_packages)))
            return asus_packages
        else:
            self._log(self._text("packages_not_found"))
            return []
    
    def detect_asus_image_type(self, img_data):
        """ASUS Detect the image type."""
        if len(img_data) < 4:
            return "img"
        
        # Convert header bytes to hex.
        header_hex = binascii.hexlify(img_data[:4]).decode('utf-8').upper()
        
        if header_hex[:4] == "424D":  # BM
            return "bmp"
        elif header_hex[:6] == "FFD8FF":  # JPEG
            return "jpg"
        elif header_hex == "89504E47":  # PNG
            return "png"
        elif header_hex == "47494638":  # GIF
            return "gif"
        elif header_hex == "00000100" or header_hex == "00000200":  # ICO
            return "ico"
        else:
            return "img"
    
    def _validate_image_replacement(self, original_image, new_data):
        """Validate image type before replacement."""
        original_type = original_image['type']
        new_type = self.detect_asus_image_type(new_data)
        
        if original_type != new_type:
            self._log(self._text("image_type_changed", original_type=original_type, new_type=new_type))
            return False
        
        return True
    
    def rebuild_asus_packer_preserve_structure(self, extracted_dir, output_file=None):
        """Repackage ASUS Packer data while preserving structure and replacing modified images only."""
        self._log(self._text("repack_title"))
        
        if not os.path.exists(extracted_dir):
            self._log(self._text("extracted_dir_missing", path=extracted_dir))
            return False
        
        # 1. 원본 바이너리에서 ASUS Packer 패키지와 이미지 메타데이터를 먼저 읽는다.
        # 리패킹은 추출 폴더 구조가 아니라 원본의 오프셋/크기/특수 패턴을 기준으로 수행된다.
        # First read ASUS Packer packages and image metadata from the original binary.
        # Repacking is based on original offsets, sizes, and special patterns, not only the extracted folder layout.
        self._log(self._text("step_analyze"))
        original_packages = self.detect_asus_packer_format()
        
        if not original_packages:
            self._log(self._text("original_package_missing"))
            return False
        
        # 2. 추출된 파일과 원본 이미지 데이터를 비교해 실제로 수정된 이미지만 수집한다.
        # 변경되지 않은 이미지는 원본 데이터를 그대로 재사용해 불필요한 구조 변화를 피한다.
        # Compare extracted files with original image bytes and keep only images that were actually modified.
        # Unchanged images reuse original data to avoid unnecessary structure changes.
        self._log(self._text("step_detect_modified"))
        modified_images = {}
        unchanged_count = 0
        modified_count = 0
        
        for pkg_idx, package in enumerate(original_packages, 1):
            pkg_dir = os.path.join(extracted_dir, f"asus_pack_{pkg_idx}")
            if not os.path.exists(pkg_dir):
                self._log(self._text("package_dir_missing", pkg_idx=pkg_idx, path=pkg_dir))
                continue
                
            for image in package['images']:
                abs_offset = image['absolute_offset']
                original_size = image['size']
                original_data = image['data']
                
                # 추출 시 생성한 파일명 규칙으로 원본 이미지와 수정 파일을 1:1로 매핑한다.
                # Map each original image to its edited file using the extraction filename convention.
                filename = f"image_nr{image['number']}_off0x{abs_offset:08x}.{image['type']}"
                filepath = os.path.join(pkg_dir, filename)
                
                # 파일명 규칙이 깨지면 오프셋 매핑을 신뢰할 수 없으므로 해당 이미지는 건너뛴다.
                # If the filename convention breaks, the offset mapping is not trustworthy, so skip the image.
                import re
                pattern = r'^image_nr(\d+)_off0x([0-9A-Fa-f]+)\.[a-zA-Z0-9]+$'
                if not re.match(pattern, filename):
                    self._log(self._text("bad_filename_pattern", filename=filename))
                    unchanged_count += 1
                    continue
                
                if os.path.exists(filepath):
                    with open(filepath, 'rb') as f:
                        extracted_data = f.read()
                    
                    # BMP/JPG/PNG 같은 컨테이너 형식이 바뀌면 펌웨어 로더가 실패할 수 있다.
                    # Changing the container type can make the firmware loader reject the image.
                    if not self._validate_image_replacement(image, extracted_data):
                        self._log(self._text("skip_type_mismatch_file", filename=filename))
                        unchanged_count += 1
                        continue
                    
                    # 바이트 단위로 비교해서 실제 변경분만 modified_images에 보관한다.
                    # Use a byte-for-byte comparison so only real edits are stored in modified_images.
                    if extracted_data == original_data:
                        unchanged_count += 1
                        self._log(self._text("unchanged_image", number=image['number'], size=len(extracted_data)))
                    else:
                        modified_count += 1
                        modified_images[abs_offset] = {
                            'original_image': image,
                            'new_data': extracted_data,
                            'new_size': len(extracted_data),
                            'size_diff': len(extracted_data) - original_size,
                            'package_idx': pkg_idx
                        }
                        self._log(self._text(
                            "modified_image",
                            number=image['number'],
                            old_size=original_size,
                            new_size=len(extracted_data),
                            diff=len(extracted_data) - original_size,
                        ))
                else:
                    self._log(self._text("extracted_file_missing", filename=filename))
        
        self._log(self._text("change_summary"))
        self._log(self._text("summary_total", count=unchanged_count + modified_count))
        self._log(self._text("summary_unchanged", count=unchanged_count))
        self._log(self._text("summary_modified", count=modified_count))
        
        if modified_count == 0:
            self._log(self._text("no_modified_copy"))
            output_file = output_file or f"{os.path.splitext(self.file_path)[0]}_asus_preserved.bin"
            
            try:
                import shutil
                shutil.copy2(self.file_path, output_file)
                self._log(self._text("copy_done", path=output_file))
                return True
            except Exception as e:
                self._log(self._text("copy_failed", error=e))
                
                return False
        
        # 3. 전체 크기 변화가 없으면 원본 오프셋에 그대로 덮어쓸 수 있다.
        # 크기가 달라진 경우에는 뒤쪽 데이터 오프셋이 밀리므로 패키지 구조를 다시 조립한다.
        # If total size does not change, edited bytes can be written back at the original offsets.
        # If sizes changed, later data shifts, so rebuild the package structure.
        self._log(self._text("step_size_change"))
        total_size_change = sum(info['size_diff'] for info in modified_images.values())
        
        if total_size_change == 0:
            self._log(self._text("total_size_no_change", change=total_size_change))
            self._log(self._text("method_direct"))
            return self._direct_replace_images(modified_images, output_file)
        else:
            self._log(self._text("total_size_change", change=total_size_change))
            self._log(self._text("method_rebuild"))
            return self._structure_preserving_rebuild(original_packages, modified_images, output_file)
    
    def _direct_replace_images(self, modified_images, output_file):
        """Direct byte replacement when sizes do not change."""
        self._log(self._text("step_direct"))
        
        # 크기 변화가 없는 경우 가장 안전한 경로다. 원본 전체를 복사한 뒤 이미지 바이트만 교체한다.
        # This is the safest path when sizes do not change: copy the original and replace only image bytes.
        new_data = bytearray(self.data)
        replaced_count = 0
        
        # 같은 크기 교체라 실제 오프셋은 변하지 않지만, 뒤에서 앞으로 처리하면 향후 확장에도 안전하다.
        # Offsets do not move for same-size replacement, but reverse order keeps this path safe for future changes.
        sorted_offsets = sorted(modified_images.keys(), reverse=True)
        
        for offset in sorted_offsets:
            info = modified_images[offset]
            original_image = info['original_image']
            new_image_data = info['new_data']
            original_size = original_image['size']
            
            # 직접 교체 경로에서는 원본 크기와 정확히 같아야 주변 메타데이터를 수정하지 않아도 된다.
            # Direct replacement requires the exact original size so surrounding metadata can remain unchanged.
            if len(new_image_data) != original_size:
                self._log(self._text("skip_size_mismatch_offset", offset=offset))
                continue
            
            # Revalidate image type.
            if not self._validate_image_replacement(original_image, new_image_data):
                self._log(self._text("skip_type_mismatch_offset", offset=offset))
                continue
            
            # 원본 바이너리의 absolute_offset 위치에 수정 이미지 바이트를 그대로 덮어쓴다.
            # Overwrite the edited image bytes at the original absolute_offset in the binary.
            new_data[offset:offset + original_size] = new_image_data
            replaced_count += 1
            
            self._log(self._text(
                "replace_done",
                offset=offset,
                number=original_image['number'],
                size=len(new_image_data),
            ))
        
        # Resolve output file name.
        if output_file is None:
            base_name = os.path.splitext(self.file_path)[0]
            output_file = f"{base_name}_asus_preserved.bin"
        
        # Write the output file.
        try:
            with open(output_file, 'wb') as f:
                f.write(new_data)
            
            self._log(self._text("direct_done"))
            self._log(self._text("replaced_images", count=replaced_count))
            self._log(self._text("file_size_no_change", size=len(new_data)))
            self._log(self._text("output_file", path=output_file))
            self._log(self._text("structure_100"))
            self._log(self._text("image_validation_done"))
            
            return True
            
        except Exception as e:
            self._log(self._text("save_failed", error=e))
            return False
    
    def _structure_preserving_rebuild(self, original_packages, modified_images, output_file):
        """Rebuild while preserving as much structure as possible when sizes change."""
        self._log(self._text("step_rebuild"))
        
        # 크기가 바뀌면 기존 오프셋 기반 덮어쓰기가 불가능하므로 새 바이너리를 앞에서부터 조립한다.
        # Size changes make offset-based overwrite invalid, so build a new binary from the front.
        new_data = bytearray()
        current_pos = 0
        total_replaced = 0
        
        for pkg_idx, package in enumerate(original_packages, 1):
            self._log(self._text("processing_package", pkg_idx=pkg_idx))
            
            # ASUS 패키지 바깥의 데이터는 해석하지 않고 원본 그대로 유지한다.
            # Data outside ASUS packages is not interpreted; preserve it exactly as-is.
            pkg_start = package['header_offset']
            if current_pos < pkg_start:
                preserved_data = self.data[current_pos:pkg_start]
                new_data.extend(preserved_data)
                self._log(self._text("preserve_before_package", size=len(preserved_data)))
            
            # 패키지 헤더는 ASUS Packer 식별에 필요한 영역이므로 원본 값을 그대로 둔다.
            # Preserve the package header because it identifies the ASUS Packer structure.
            header_end = package['header_end']
            original_header = self.data[pkg_start:header_end]
            new_data.extend(original_header)
            self._log(self._text("preserve_header", size=len(original_header)))
            
            # 각 이미지는 [크기 4B][상대 오프셋 4B][특수 패턴 24B][이미지 데이터][패딩] 순서로 재조립한다.
            # Rebuild each image block as [size 4B][relative offset 4B][special pattern 24B][image data][padding].
            pkg_replaced_count = 0
            
            # 이미지 순서는 펌웨어 내부 참조와 연결될 수 있어 원본 번호 순서를 유지한다.
            # Keep the original image order because firmware references may depend on it.
            sorted_images = sorted(package['images'], key=lambda x: x['number'])
            
            for img_info in sorted_images:
                abs_offset = img_info['absolute_offset']
                
                # 변경된 이미지만 새 데이터를 사용하고, 나머지는 원본 이미지 데이터를 그대로 넣는다.
                # Use edited data only for modified images; all others keep their original bytes.
                if abs_offset in modified_images:
                    # Use modified image data.
                    img_data = modified_images[abs_offset]['new_data']
                    pkg_replaced_count += 1
                    total_replaced += 1
                    self._log(self._text(
                        "replace_image",
                        number=img_info['number'],
                        old_size=img_info['size'],
                        new_size=len(img_data),
                    ))
                else:
                    # Preserve original image data.
                    img_data = img_info['data']
                    self._log(self._text("preserve_image", number=img_info['number'], size=len(img_data)))
                
                # 메타데이터의 첫 4바이트는 현재 이미지 크기다. 크기가 바뀐 이미지는 여기서 갱신된다.
                # The first 4 metadata bytes store the current image size, updated for resized images.
                size_bytes = struct.pack('<I', len(img_data))
                new_data.extend(size_bytes)
                
                # 다음 4바이트는 메타데이터 시작점 기준 이미지 데이터까지의 상대 오프셋이다.
                # 현재 구조는 32바이트 메타데이터 뒤에 이미지가 오므로 0x20으로 고정한다.
                # The next 4 bytes are the relative offset from metadata start to image data.
                # This layout places image data after a 32-byte metadata block, so the offset stays 0x20.
                offset_bytes = struct.pack('<I', 0x20)
                new_data.extend(offset_bytes)
                
                # 나머지 24바이트는 모델별 의미가 명확하지 않은 특수 패턴이라 원본 보존이 우선이다.
                # The remaining 24 bytes are model-specific/unclear, so preserving the original pattern is safest.
                original_special_pattern = img_info.get('special_pattern')
                if original_special_pattern and len(original_special_pattern) == 24:
                    new_data.extend(original_special_pattern)
                    self._log(self._text("preserve_special"))
                else:
                    # Fallback: extract directly from the original file.
                    metadata_start = img_info['metadata_offset']
                    if metadata_start + 32 <= len(self.data):
                        original_special_pattern = self.data[metadata_start + 8:metadata_start + 32]
                        new_data.extend(original_special_pattern)
                        self._log(self._text("extract_special"))
                    else:
                        # Last resort: use the default pattern.
                        if img_info['number'] == 1:
                            special_pattern = bytes.fromhex("FFFF0A00FFFF004000000000300009040000000000000000")
                        else:
                            special_pattern = bytes.fromhex("00FFFF0A00FFFF0200000000300009040000000000000000")
                        new_data.extend(special_pattern)
                        self._log(self._text("default_special"))
                
                # 갱신된 메타데이터 바로 뒤에 실제 이미지 데이터를 붙인다.
                # Append actual image data directly after the updated metadata.
                new_data.extend(img_data)
                
                # ASUS 패키지는 이미지 뒤를 4바이트 경계로 맞추므로 동일한 정렬을 적용한다.
                # ASUS packages align image payloads to 4-byte boundaries; apply the same alignment.
                padding = (4 - (len(img_data) % 4)) % 4
                if padding > 0:
                    new_data.extend(b'\x00' * padding)
                    self._log(self._text("add_padding", padding=padding))
            
            # 원본 기준으로 현재 패키지가 차지하던 범위를 건너뛰고 다음 보존 구간을 계산한다.
            # Advance over the original package span to find the next untouched region to preserve.
            current_pos = pkg_start + package['total_size']
            
            self._log(self._text("package_complete", pkg_idx=pkg_idx))
            self._log(self._text("package_replaced", count=pkg_replaced_count))
            self._log(self._text("package_total", count=len(sorted_images)))
            self._log(self._text("package_special_preserved"))
            self._log(self._text("package_structure"))
        
        # Preserve all data after the last package.
        if current_pos < len(self.data):
            remaining_data = self.data[current_pos:]
            new_data.extend(remaining_data)
            self._log(self._text("preserve_after_package", size=len(remaining_data)))
        
        # Resolve output file name.
        if output_file is None:
            base_name = os.path.splitext(self.file_path)[0]
            output_file = f"{base_name}_asus_preserved.bin"
        
        # Write the output file.
        try:
            with open(output_file, 'wb') as f:
                f.write(new_data)
            
            self._log(self._text("rebuild_done"))
            self._log(self._text("replaced_images", count=total_replaced))
            self._log(self._text("original_size", size=len(self.data)))
            self._log(self._text("final_size", size=len(new_data)))
            self._log(self._text("size_diff", diff=len(new_data) - len(self.data)))
            self._log(self._text("output_file", path=output_file))
            self._log(self._text("structure_max"))
            self._log(self._text("image_validation_done"))
            
            return True
            
        except Exception as e:
            self._log(self._text("save_failed", error=e))
            return False
    
    def run_repack(self, extracted_dir, output_file=None):
        """Run the full repack workflow."""
        self._log(self._text("start"))
        self._log("=" * 60)
        
        self.load_file()
        
        success = self.rebuild_asus_packer_preserve_structure(extracted_dir, output_file)
        
        
        if success:
            self._log("\n" + "=" * 60)
            self._log(self._text("success"))
            self._log("=" * 60)
        else:
            self._log("\n" + "=" * 60)
            self._log(self._text("failed"))
            self._log("=" * 60)
        
        return success
