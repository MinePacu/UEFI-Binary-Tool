#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ASUS 이미지 리패커
추출된 이미지를 다시 ASUS Packer 형식으로 재패키징
"""

import os
import re
import binascii
import struct
from datetime import datetime


class AsusImageRepacker:
    def __init__(self, file_path):
        self.file_path = file_path
        self.file_size = os.path.getsize(file_path)
        self.data = None
        
    def load_file(self):
        """파일을 메모리에 로드"""
        with open(self.file_path, 'rb') as f:
            self.data = f.read()
        print(f"원본 파일 로드 완료: {self.file_path}")
        print(f"파일 크기: {self.file_size:,} bytes ({self.file_size / 1024 / 1024:.2f} MB)")
    
    def detect_asus_packer_format(self):
        """ASUS Packer 형식 감지"""
        print("\n=== ASUS Packer 형식 감지 ===")
        
        # ASUS Packer 시그니처 패턴
        asus_pattern = re.compile(br'\x00\x00\x00\x00\x20\x00\x00\x00\xFF\xFF\x00\x00\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        
        asus_packages = []
        position = 0
        
        while True:
            match = asus_pattern.search(self.data, position)
            if match is None:
                break
            
            start_match, end_match = match.span()
            print(f"ASUS Packer 패키지 발견: 오프셋 0x{start_match:08x}")
            
            # 헤더 이후 이미지 메타데이터 파싱
            head = end_match
            images = []
            image_nr = 0
            
            while True:
                if head + 8 > len(self.data):
                    break
                    
                # 이미지 크기와 오프셋 읽기 (little-endian)
                isize_bytes = self.data[head:head + 4]
                ioffs_bytes = self.data[head + 4:head + 8]
                
                if len(isize_bytes) < 4 or len(ioffs_bytes) < 4:
                    break
                    
                isize = struct.unpack('<I', isize_bytes)[0]
                ioffs = struct.unpack('<I', ioffs_bytes)[0]
                
                # 유효성 검사
                if isize == 0 or ioffs == 0:
                    break
                    
                # 특별한 헤더 패턴 확인
                check_offset = head + ioffs - 0x10
                if check_offset >= 0 and check_offset + 16 <= len(self.data):
                    check_pattern = self.data[check_offset:check_offset + 16]
                    expected_pattern = bytes.fromhex("00000000300009040000000000000000")
                    if check_pattern != expected_pattern:
                        break
                
                # 이미지 데이터 위치
                img_start = head + ioffs
                img_end = img_start + isize
                
                if img_end > len(self.data):
                    break
                    
                # 이미지 타입 감지
                img_data = self.data[img_start:img_end]
                img_type = self.detect_asus_image_type(img_data)
                
                image_nr += 1
                # 원본 특별 패턴 24바이트 보존
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
                
                print(f"  이미지 #{image_nr}: {img_type}, 크기={isize}, 오프셋=0x{img_start:08x}")
                
                # 다음 메타데이터 위치로 이동 (정확한 32바이트 메타데이터 + 이미지 크기 + 4바이트 정렬)
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
            print(f"패키지 완료: {len(images)}개 이미지, 총 크기={head - start_match} bytes\n")
        
        if asus_packages:
            print(f"총 {len(asus_packages)}개의 ASUS Packer 패키지 발견")
            return asus_packages
        else:
            print("ASUS Packer 패키지를 찾을 수 없습니다.")
            return []
    
    def detect_asus_image_type(self, img_data):
        """ASUS 이미지 타입 감지"""
        if len(img_data) < 4:
            return "img"
        
        # 헤더 바이트를 헥스로 변환
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
        """이미지 교체 시 형식 검증"""
        original_type = original_image['type']
        new_type = self.detect_asus_image_type(new_data)
        
        if original_type != new_type:
            print(f"  ⚠️ 경고: 이미지 형식 변경 감지 ({original_type} → {new_type})")
            return False
        
        return True
    
    def rebuild_asus_packer_preserve_structure(self, extracted_dir, output_file=None):
        """원본 구조를 최대한 보존하면서 수정된 이미지만 교체하는 ASUS Packer 재패키징"""
        print(f"\n=== ASUS Packer 원본 구조 보존 재패키징 ===")
        
        if not os.path.exists(extracted_dir):
            print(f"오류: 추출된 파일 디렉터리를 찾을 수 없습니다 - {extracted_dir}")
            return False
        
        # 1. 원본 ASUS 패키지 구조 분석
        print("1단계: 원본 ASUS 패키지 구조 분석...")
        original_packages = self.detect_asus_packer_format()
        
        if not original_packages:
            print("오류: 원본 파일에서 ASUS 패키지를 찾을 수 없습니다.")
            return False
        
        # 2. 수정된 이미지 파일 감지
        print("2단계: 수정된 이미지 파일 감지...")
        modified_images = {}
        unchanged_count = 0
        modified_count = 0
        
        for pkg_idx, package in enumerate(original_packages, 1):
            pkg_dir = os.path.join(extracted_dir, f"asus_pack_{pkg_idx}")
            if not os.path.exists(pkg_dir):
                print(f"  경고: 패키지 {pkg_idx} 디렉터리가 없습니다: {pkg_dir}")
                continue
                
            for image in package['images']:
                abs_offset = image['absolute_offset']
                original_size = image['size']
                original_data = image['data']
                
                # 추출된 파일 찾기
                filename = f"image_nr{image['number']}_off0x{abs_offset:08x}.{image['type']}"
                filepath = os.path.join(pkg_dir, filename)
                
                # 파일명 패턴 검증
                import re
                pattern = r'^image_nr(\d+)_off0x([0-9A-Fa-f]+)\.[a-zA-Z0-9]+$'
                if not re.match(pattern, filename):
                    print(f"  [WARNING] 생성된 파일명 패턴이 올바르지 않음 (image_nr{{숫자}}_off0x{{16진수}}.{{확장자}} 형식이어야 함): {filename}")
                    unchanged_count += 1
                    continue
                
                if os.path.exists(filepath):
                    with open(filepath, 'rb') as f:
                        extracted_data = f.read()
                    
                    # 이미지 형식 검증
                    if not self._validate_image_replacement(image, extracted_data):
                        print(f"  ❌ 형식 불일치로 건너뛰기: {filename}")
                        unchanged_count += 1
                        continue
                    
                    # 원본과 추출된 파일 비교
                    if extracted_data == original_data:
                        unchanged_count += 1
                        print(f"  변경없음: 이미지 #{image['number']} ({len(extracted_data)} bytes)")
                    else:
                        modified_count += 1
                        modified_images[abs_offset] = {
                            'original_image': image,
                            'new_data': extracted_data,
                            'new_size': len(extracted_data),
                            'size_diff': len(extracted_data) - original_size,
                            'package_idx': pkg_idx
                        }
                        print(f"  🔄 수정됨: 이미지 #{image['number']} "
                              f"({original_size} → {len(extracted_data)} bytes, "
                              f"{len(extracted_data) - original_size:+} bytes)")
                else:
                    print(f"  경고: 추출된 파일을 찾을 수 없습니다: {filename}")
        
        print(f"\n변경 요약:")
        print(f"  📋 총 이미지: {unchanged_count + modified_count}개")
        print(f"  ✅ 변경없음: {unchanged_count}개")
        print(f"  🔄 수정됨: {modified_count}개")
        
        if modified_count == 0:
            print("수정된 이미지가 없으므로 원본 파일을 그대로 복사합니다.")
            output_file = output_file or f"{os.path.splitext(self.file_path)[0]}_asus_preserved.bin"
            
            try:
                import shutil
                shutil.copy2(self.file_path, output_file)
                print(f"원본 파일 복사 완료: {output_file}")
                return True
            except Exception as e:
                print(f"파일 복사 실패: {e}")
                
                return False
        
        # 3. 크기 변화 분석
        print("3단계: 크기 변화 분석...")
        total_size_change = sum(info['size_diff'] for info in modified_images.values())
        
        if total_size_change == 0:
            print(f"  📊 총 크기 변화: {total_size_change} bytes (변화 없음)")
            print("  🔧 처리 방식: 바이트 단위 직접 교체")
            return self._direct_replace_images(modified_images, output_file)
        else:
            print(f"  📊 총 크기 변화: {total_size_change:+} bytes")
            print("  🔧 처리 방식: 구조 보존 재구성")
            return self._structure_preserving_rebuild(original_packages, modified_images, output_file)
    
    def _direct_replace_images(self, modified_images, output_file):
        """크기 변화가 없는 경우 바이트 단위 직접 교체"""
        print("\n4단계: 바이트 단위 직접 교체...")
        
        # 원본 데이터 전체 복사
        new_data = bytearray(self.data)
        replaced_count = 0
        
        # 오프셋 순으로 정렬하여 처리 (역순으로 처리하여 오프셋 변화 방지)
        sorted_offsets = sorted(modified_images.keys(), reverse=True)
        
        for offset in sorted_offsets:
            info = modified_images[offset]
            original_image = info['original_image']
            new_image_data = info['new_data']
            original_size = original_image['size']
            
            # 크기 검증
            if len(new_image_data) != original_size:
                print(f"  ❌ 크기 불일치로 건너뛰기: 오프셋 0x{offset:08x}")
                continue
            
            # 이미지 형식 재검증
            if not self._validate_image_replacement(original_image, new_image_data):
                print(f"  ❌ 형식 불일치로 건너뛰기: 오프셋 0x{offset:08x}")
                continue
            
            # 원본 위치에 새 이미지 데이터 교체
            new_data[offset:offset + original_size] = new_image_data
            replaced_count += 1
            
            print(f"  ✅ 교체 완료: 오프셋 0x{offset:08x}, "
                  f"이미지 #{original_image['number']}, {len(new_image_data)} bytes")
        
        # 출력 파일명 설정
        if output_file is None:
            base_name = os.path.splitext(self.file_path)[0]
            output_file = f"{base_name}_asus_preserved.bin"
        
        # 파일 저장
        try:
            with open(output_file, 'wb') as f:
                f.write(new_data)
            
            print(f"\n✅ 바이트 단위 교체 완료:")
            print(f"  🔄 교체된 이미지: {replaced_count}개")
            print(f"  📏 파일 크기: {len(new_data):,} bytes (변화 없음)")
            print(f"  📁 출력 파일: {output_file}")
            print(f"  🎯 구조 보존: 100% (원본과 동일)")
            print(f"  ✅ 이미지 형식 검증: 완료")
            
            return True
            
        except Exception as e:
            print(f"❌ 파일 저장 실패: {e}")
            return False
    
    def _structure_preserving_rebuild(self, original_packages, modified_images, output_file):
        """크기 변화가 있는 경우 구조를 최대한 보존하며 재구성"""
        print("\n4단계: 원본 ASUS 구조 완전 복원...")
        
        new_data = bytearray()
        current_pos = 0
        total_replaced = 0
        
        for pkg_idx, package in enumerate(original_packages, 1):
            print(f"\n  📦 패키지 {pkg_idx} 처리 중...")
            
            # 패키지 시작 전의 모든 데이터 보존
            pkg_start = package['header_offset']
            if current_pos < pkg_start:
                preserved_data = self.data[current_pos:pkg_start]
                new_data.extend(preserved_data)
                print(f"    📋 패키지 전 데이터 보존: {len(preserved_data)} bytes")
            
            # 원본 ASUS 헤더 완전 보존 (32바이트)
            header_end = package['header_end']
            original_header = self.data[pkg_start:header_end]
            new_data.extend(original_header)
            print(f"    🏷️ ASUS 헤더 보존: {len(original_header)} bytes")
            
            # 원본 구조 완전 복원: 메타데이터와 이미지가 인터리브된 구조
            pkg_replaced_count = 0
            
            # 원본 순서 유지를 위해 번호 순으로 정렬
            sorted_images = sorted(package['images'], key=lambda x: x['number'])
            
            for img_info in sorted_images:
                abs_offset = img_info['absolute_offset']
                
                # 수정된 이미지인지 확인
                if abs_offset in modified_images:
                    # 수정된 이미지 사용
                    img_data = modified_images[abs_offset]['new_data']
                    pkg_replaced_count += 1
                    total_replaced += 1
                    print(f"      🔄 교체: 이미지 #{img_info['number']} "
                          f"({img_info['size']} → {len(img_data)} bytes)")
                else:
                    # 원본 이미지 보존
                    img_data = img_info['data']
                    print(f"      ✅ 보존: 이미지 #{img_info['number']} ({len(img_data)} bytes)")
                
                # **핵심 개선**: 원본 메타데이터 구조 완전 보존
                # 4바이트: 이미지 크기 (업데이트된 크기)
                size_bytes = struct.pack('<I', len(img_data))
                new_data.extend(size_bytes)
                
                # 4바이트: 상대 오프셋 (고정 0x20)
                offset_bytes = struct.pack('<I', 0x20)
                new_data.extend(offset_bytes)
                
                # **중요**: 원본 특별 패턴 24바이트를 그대로 보존
                original_special_pattern = img_info.get('special_pattern')
                if original_special_pattern and len(original_special_pattern) == 24:
                    new_data.extend(original_special_pattern)
                    print(f"        🔧 원본 특별 패턴 보존: 24 bytes")
                else:
                    # 원본 파일에서 직접 추출 (fallback)
                    metadata_start = img_info['metadata_offset']
                    if metadata_start + 32 <= len(self.data):
                        original_special_pattern = self.data[metadata_start + 8:metadata_start + 32]
                        new_data.extend(original_special_pattern)
                        print(f"        🔧 원본 특별 패턴 추출 보존: 24 bytes")
                    else:
                        # 최후의 수단: 기본 패턴 사용
                        if img_info['number'] == 1:
                            special_pattern = bytes.fromhex("FFFF0A00FFFF004000000000300009040000000000000000")
                        else:
                            special_pattern = bytes.fromhex("00FFFF0A00FFFF0200000000300009040000000000000000")
                        new_data.extend(special_pattern)
                        print(f"        ⚠️ 기본 특별 패턴 사용: 24 bytes")
                
                # 이미지 데이터 추가
                new_data.extend(img_data)
                
                # 원본과 동일한 4바이트 정렬 적용
                padding = (4 - (len(img_data) % 4)) % 4
                if padding > 0:
                    new_data.extend(b'\x00' * padding)
                    print(f"        🔧 패딩 추가: {padding} bytes (4바이트 정렬)")
            
            # 다음 패키지 시작 위치 업데이트
            current_pos = pkg_start + package['total_size']
            
            print(f"    📊 패키지 {pkg_idx} 완료:")
            print(f"      - 교체된 이미지: {pkg_replaced_count}개")
            print(f"      - 총 이미지: {len(sorted_images)}개")
            print(f"      - 원본 특별 패턴 보존: ✅")
            print(f"      - 구조 복원: 메타데이터+원본패턴+이미지 인터리브")
        
        # 마지막 패키지 이후의 모든 데이터 보존
        if current_pos < len(self.data):
            remaining_data = self.data[current_pos:]
            new_data.extend(remaining_data)
            print(f"\n  📋 패키지 후 데이터 보존: {len(remaining_data)} bytes")
        
        # 출력 파일명 설정
        if output_file is None:
            base_name = os.path.splitext(self.file_path)[0]
            output_file = f"{base_name}_asus_preserved.bin"
        
        # 파일 저장
        try:
            with open(output_file, 'wb') as f:
                f.write(new_data)
            
            print(f"\n✅ 구조 보존 재구성 완료:")
            print(f"  🔄 교체된 이미지: {total_replaced}개")
            print(f"  📏 원본 크기: {len(self.data):,} bytes")
            print(f"  📏 최종 크기: {len(new_data):,} bytes")
            print(f"  📊 크기 변화: {len(new_data) - len(self.data):+,} bytes")
            print(f"  📁 출력 파일: {output_file}")
            print(f"  🎯 구조 보존: 최대화 (헤더, 원본 특별패턴, 순서, 패딩 모두 보존)")
            print(f"  ✅ 이미지 형식 검증: 완료")
            
            return True
            
        except Exception as e:
            print(f"❌ 파일 저장 실패: {e}")
            return False
    
    def run_repack(self, extracted_dir, output_file=None):
        """전체 리패킹 작업 실행"""
        print("ASUS 이미지 리패킹을 시작합니다...")
        print("=" * 60)
        
        self.load_file()
        
        success = self.rebuild_asus_packer_preserve_structure(extracted_dir, output_file)
        
        
        if success:
            print("\n" + "=" * 60)
            print("[SUCCESS] ASUS 이미지 리패킹이 완료되었습니다!")
            print("=" * 60)
        else:
            print("\n" + "=" * 60)
            print("[ERROR] ASUS 이미지 리패킹이 실패했습니다.")
            print("=" * 60)
        
        return success
