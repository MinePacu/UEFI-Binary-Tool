#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ASUS 바이너리 파일 분석기
ASUS BIOS/UEFI 파일의 구조 분석 및 매직 바이트 감지
"""

import os
import re
import binascii
import struct
from collections import defaultdict
from datetime import datetime


class AsusFileAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.file_size = os.path.getsize(file_path)
        self.data = None
        
    def load_file(self):
        """파일을 메모리에 로드"""
        with open(self.file_path, 'rb') as f:
            self.data = f.read()
        print(f"파일 로드 완료: {self.file_path}")
        print(f"파일 크기: {self.file_size:,} bytes ({self.file_size / 1024 / 1024:.2f} MB)")
        
    def analyze_magic_bytes(self):
        """매직 바이트 패턴 분석"""
        print("\n=== 매직 바이트 분석 ===")
        
        # 알려진 매직 바이트 패턴들
        magic_patterns = {
            b'MZ': 'PE/DOS Executable',
            b'PE\x00\x00': 'PE Header',
            b'\x7fELF': 'ELF Binary',
            b'PK\x03\x04': 'ZIP Archive',
            b'\x1f\x8b': 'GZIP',
            b'BM': 'Bitmap Image',
            b'\xff\xd8\xff': 'JPEG Image',
            b'\x89PNG': 'PNG Image',
            b'GIF8': 'GIF Image',
            b'RIFF': 'RIFF Container',
            b'\x00\x00\x01\x00': 'ICO File',
            b'_FVH': 'UEFI Firmware Volume',
            b'\x16\x00\x00\x00': 'Possible UEFI Volume',
            b'$FV$': 'UEFI Firmware Volume Signature',
            b'\x78\x56\x34\x12': 'Little Endian Magic',
            b'\x12\x34\x56\x78': 'Big Endian Magic',
        }
        
        # 파일 시작 부분의 매직 바이트 확인
        found_magic = []
        for length in [2, 3, 4, 8, 16]:
            if len(self.data) >= length:
                header = self.data[:length]
                for magic, description in magic_patterns.items():
                    if header.startswith(magic):
                        print(f"매직 바이트 발견: {binascii.hexlify(magic).decode()} - {description}")
                        found_magic.append((magic, description))
        
        # 매직 바이트 패턴 빈도 분석
        print(f"\n=== 매직 패턴 빈도 분석 ===")
        magic_frequency = []
        
        for magic_bytes, description in magic_patterns.items():
            count = self.data.count(magic_bytes)
            if count > 0:
                frequency_per_mb = round(count / (self.file_size / 1024 / 1024), 2) if self.file_size > 0 else 0
                print(f"{binascii.hexlify(magic_bytes).decode()} ({description}): {count}개 ({frequency_per_mb}/MB)")
                magic_frequency.append((description, count, frequency_per_mb))
        
        if magic_frequency:
            print(f"\n매직 패턴 빈도 요약:")
            magic_frequency.sort(key=lambda x: x[1], reverse=True)  # 개수로 정렬
            print(f"{'패턴':<25} {'개수':>6} {'빈도(/MB)':>10}")
            print("-" * 45)
            for desc, count, freq in magic_frequency[:5]:  # 상위 5개만 표시
                print(f"{desc:<25} {count:>6} {freq:>10}")
        
        # 헥스 덤프 (처음 64바이트)
        print(f"\n파일 시작 64바이트 헥스 덤프:")
        hex_data = binascii.hexlify(self.data[:64]).decode()
        for i in range(0, len(hex_data), 32):
            offset = i // 2
            hex_line = hex_data[i:i+32]
            formatted_hex = ' '.join(hex_line[j:j+2] for j in range(0, len(hex_line), 2))
            ascii_data = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in self.data[offset:offset+16])
            print(f"{offset:08x}: {formatted_hex:<47} |{ascii_data}|")
    
    def find_patterns(self):
        """파일 내에서 반복되는 패턴 찾기"""
        print("\n=== 패턴 분석 ===")
        
        # 특정 패턴들 검색
        patterns = {
            b'\x00' * 16: '16바이트 NULL 패턴',
            b'\xff' * 16: '16바이트 0xFF 패턴',
            b'UEFI': 'UEFI 문자열',
            b'BIOS': 'BIOS 문자열',
            b'Award': 'Award BIOS',
            b'AMI': 'AMI BIOS',
            b'Phoenix': 'Phoenix BIOS',
            b'ASUS': 'ASUS 관련',
            b'Intel': 'Intel 관련',
            b'AMD': 'AMD 관련',
            b'\x89PNG': 'PNG 이미지',
            b'\xff\xd8\xff': 'JPEG 이미지',
            b'BM': 'BMP 이미지',
            b'GIF8': 'GIF 이미지',
            b'RIFF': 'RIFF 파일',
            b'IEND': 'PNG 종료 마커',
        }
        
        # 패턴 빈도 통계
        pattern_stats = []
        
        for pattern, description in patterns.items():
            count = self.data.count(pattern)
            if count > 0:
                positions = []
                start = 0
                for _ in range(min(count, 5)):  # 최대 5개 위치만 표시
                    pos = self.data.find(pattern, start)
                    if pos != -1:
                        positions.append(f"0x{pos:08x}")
                        start = pos + 1
                    else:
                        break
                
                density_per_kb = round(count / (self.file_size / 1024), 3) if self.file_size > 0 else 0
                percentage_of_file = round((count * len(pattern) / self.file_size) * 100, 4) if self.file_size > 0 else 0
                
                print(f"{description}: {count}개 발견 (밀도: {density_per_kb}/KB, 비율: {percentage_of_file}%)")
                print(f"  위치: {', '.join(positions)}")
                if count > 5:
                    print(f"  (총 {count}개, 처음 5개만 표시)")
                
                pattern_stats.append((description, count, density_per_kb, percentage_of_file))
        
        # 빈도 통계 요약
        if pattern_stats:
            print(f"\n=== 패턴 빈도 요약 (상위 5개) ===")
            pattern_stats.sort(key=lambda x: x[1], reverse=True)  # 개수로 정렬
            print(f"{'패턴':<20} {'개수':>8} {'밀도(/KB)':>10} {'비율(%)':>8}")
            print("-" * 50)
            for desc, count, density, percentage in pattern_stats[:5]:
                print(f"{desc:<20} {count:>8} {density:>10} {percentage:>8}")
    
    def analyze_embedded_files(self):
        """임베디드 파일 분석"""
        print("\n=== 임베디드 파일 분석 ===")
        
        embedded_files = []
        
        # PNG 파일 찾기
        png_start = 0
        while True:
            png_pos = self.data.find(b'\x89PNG\r\n\x1a\n', png_start)
            if png_pos == -1:
                break
            
            # PNG 끝 찾기 (IEND 청크)
            iend_pos = self.data.find(b'IEND\xaeB`\x82', png_pos)
            if iend_pos != -1:
                png_size = iend_pos + 8 - png_pos
                embedded_files.append({
                    'type': 'PNG Image',
                    'start': png_pos,
                    'size': png_size,
                    'end': png_pos + png_size
                })
            png_start = png_pos + 1
        
        # JPEG 파일 찾기
        jpeg_start = 0
        while True:
            jpeg_pos = self.data.find(b'\xff\xd8\xff', jpeg_start)
            if jpeg_pos == -1:
                break
            
            # JPEG 끝 찾기 (FFD9)
            search_pos = jpeg_pos + 3
            jpeg_end = -1
            while search_pos < len(self.data) - 1:
                if self.data[search_pos:search_pos+2] == b'\xff\xd9':
                    jpeg_end = search_pos + 2
                    break
                search_pos += 1
            
            if jpeg_end != -1:
                jpeg_size = jpeg_end - jpeg_pos
                embedded_files.append({
                    'type': 'JPEG Image',
                    'start': jpeg_pos,
                    'size': jpeg_size,
                    'end': jpeg_end
                })
            jpeg_start = jpeg_pos + 1
        
        # BMP 파일 찾기
        bmp_start = 0
        while True:
            bmp_pos = self.data.find(b'BM', bmp_start)
            if bmp_pos == -1:
                break
            
            # BMP 헤더에서 파일 크기 읽기
            if bmp_pos + 6 <= len(self.data):
                try:
                    bmp_size_bytes = self.data[bmp_pos + 2:bmp_pos + 6]
                    bmp_size = struct.unpack('<I', bmp_size_bytes)[0]
                    
                    # 합리적인 크기 범위 확인
                    if 100 <= bmp_size <= 50 * 1024 * 1024 and bmp_pos + bmp_size <= len(self.data):
                        embedded_files.append({
                            'type': 'BMP Image',
                            'start': bmp_pos,
                            'size': bmp_size,
                            'end': bmp_pos + bmp_size
                        })
                except:
                    pass
            bmp_start = bmp_pos + 1
        
        # 발견된 임베디드 파일들 출력
        if embedded_files:
            print("발견된 임베디드 파일들:")
            for i, file_info in enumerate(embedded_files, 1):
                print(f"  {i}. {file_info['type']}")
                print(f"     위치: 0x{file_info['start']:08x} - 0x{file_info['end']:08x}")
                print(f"     크기: {file_info['size']:,} bytes ({file_info['size']/1024:.1f} KB)")
                
                # PNG인 경우 추가 정보 추출
                if file_info['type'] == 'PNG Image':
                    self.analyze_png_details(file_info['start'])
                # BMP인 경우 추가 정보 추출
                elif file_info['type'] == 'BMP Image':
                    self.analyze_bmp_details(file_info['start'])
        else:
            print("임베디드 파일이 발견되지 않았습니다.")
    
    def analyze_png_details(self, png_start):
        """PNG 파일의 세부 정보 분석"""
        try:
            # IHDR 청크에서 이미지 정보 추출
            ihdr_pos = self.data.find(b'IHDR', png_start)
            if ihdr_pos != -1:
                # IHDR 데이터는 IHDR 문자열 바로 다음 13바이트
                ihdr_data = self.data[ihdr_pos + 4:ihdr_pos + 17]
                if len(ihdr_data) >= 13:
                    width, height, bit_depth, color_type = struct.unpack('>IIBBB', ihdr_data[:9])
                    print(f"       PNG 정보: {width}x{height}, {bit_depth}bit, 컬러타입={color_type}")
            
            # 텍스트 청크 찾기
            text_chunks = [b'tEXt', b'iTXt', b'zTXt']
            for chunk_type in text_chunks:
                chunk_pos = self.data.find(chunk_type, png_start)
                if chunk_pos != -1:
                    # 청크 길이 읽기 (청크 타입 4바이트 전)
                    length_data = self.data[chunk_pos-4:chunk_pos]
                    if len(length_data) == 4:
                        chunk_length = struct.unpack('>I', length_data)[0]
                        if chunk_length < 1000:  # 합리적인 크기 제한
                            text_data = self.data[chunk_pos+4:chunk_pos+4+chunk_length]
                            # 인쇄 가능한 문자만 추출
                            readable_text = ''.join(chr(b) if 32 <= b <= 126 else ' ' for b in text_data[:100])
                            print(f"       텍스트 정보: {readable_text.strip()}")
                            break
        except:
            pass
    
    def analyze_bmp_details(self, bmp_start):
        """BMP 파일의 세부 정보 분석"""
        try:
            # BMP 헤더 분석 (최소 54바이트 필요)
            if bmp_start + 54 <= len(self.data):
                # BMP 파일 헤더 (14바이트)
                file_size = struct.unpack('<I', self.data[bmp_start + 2:bmp_start + 6])[0]
                data_offset = struct.unpack('<I', self.data[bmp_start + 10:bmp_start + 14])[0]
                
                # DIB 헤더 (최소 40바이트)
                dib_header_size = struct.unpack('<I', self.data[bmp_start + 14:bmp_start + 18])[0]
                
                if dib_header_size >= 40:  # BITMAPINFOHEADER 또는 더 큰 헤더
                    width = struct.unpack('<i', self.data[bmp_start + 18:bmp_start + 22])[0]
                    height = struct.unpack('<i', self.data[bmp_start + 22:bmp_start + 26])[0]
                    planes = struct.unpack('<H', self.data[bmp_start + 26:bmp_start + 28])[0]
                    bit_count = struct.unpack('<H', self.data[bmp_start + 28:bmp_start + 30])[0]
                    compression = struct.unpack('<I', self.data[bmp_start + 30:bmp_start + 34])[0]
                    
                    # 압축 타입 해석
                    compression_types = {
                        0: 'BI_RGB (무압축)',
                        1: 'BI_RLE8',
                        2: 'BI_RLE4',
                        3: 'BI_BITFIELDS'
                    }
                    compression_str = compression_types.get(compression, f'알 수 없음 ({compression})')
                    
                    print(f"       BMP 정보: {abs(width)}x{abs(height)}, {bit_count}bit, {compression_str}")
                    if height < 0:
                        print(f"       (상하 반전 이미지)")
        except:
            pass
    
    def analyze_entropy(self, block_size=1024):
        """엔트로피 분석으로 압축/암호화 영역 감지"""
        print(f"\n=== 엔트로피 분석 (블록 크기: {block_size}바이트) ===")
        
        import math
        
        high_entropy_blocks = []
        low_entropy_blocks = []
        
        for i in range(0, len(self.data), block_size):
            block = self.data[i:i+block_size]
            if len(block) < block_size // 2:  # 너무 작은 블록은 건너뛰기
                continue
                
            # 바이트 빈도 계산
            byte_counts = defaultdict(int)
            for byte in block:
                byte_counts[byte] += 1
            
            # 엔트로피 계산
            entropy = 0
            for count in byte_counts.values():
                p = count / len(block)
                if p > 0:
                    entropy -= p * math.log2(p)
            
            # 높은 엔트로피 (압축/암호화 가능성) 또는 낮은 엔트로피 (반복 패턴) 블록 기록
            if entropy > 7.5:
                high_entropy_blocks.append((i, entropy))
            elif entropy < 2.0:
                low_entropy_blocks.append((i, entropy))
        
        if high_entropy_blocks:
            print("높은 엔트로피 영역 (압축/암호화 가능성):")
            for offset, entropy in high_entropy_blocks[:10]:  # 최대 10개만 표시
                print(f"  오프셋 0x{offset:08x}: 엔트로피 {entropy:.2f}")
        
        if low_entropy_blocks:
            print("낮은 엔트로피 영역 (반복 패턴/빈 공간):")
            for offset, entropy in low_entropy_blocks[:10]:  # 최대 10개만 표시
                print(f"  오프셋 0x{offset:08x}: 엔트로피 {entropy:.2f}")
    
    def analyze_structure(self):
        """파일 구조 분석"""
        print("\n=== 구조 분석 ===")
        
        # 32비트/64비트 정렬 확인
        null_sequences = []
        i = 0
        while i < len(self.data) - 4:
            if self.data[i:i+4] == b'\x00\x00\x00\x00':
                start = i
                while i < len(self.data) and self.data[i] == 0:
                    i += 1
                null_sequences.append((start, i - start))
            else:
                i += 1
        
        if null_sequences:
            print("NULL 바이트 시퀀스 (패딩/정렬 가능성):")
            for start, length in null_sequences[:10]:  # 최대 10개만 표시
                print(f"  오프셋 0x{start:08x}: {length}바이트")
        
        # 16바이트 정렬 구조 확인 (UEFI에서 일반적)
        aligned_positions = []
        for i in range(0, len(self.data), 16):
            if i + 16 <= len(self.data):
                block = self.data[i:i+16]
                # 특별한 패턴이나 헤더 같은 구조 확인
                if not all(b == 0 for b in block) and not all(b == 0xff for b in block):
                    # 인쇄 가능한 문자가 있는지 확인
                    printable_count = sum(1 for b in block if 32 <= b <= 126)
                    if printable_count >= 4:  # 최소 4개의 인쇄 가능한 문자
                        aligned_positions.append(i)
        
        if aligned_positions:
            print("16바이트 정렬된 텍스트/구조 블록:")
            for pos in aligned_positions[:10]:  # 최대 10개만 표시
                block = self.data[pos:pos+16]
                text = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in block)
                print(f"  오프셋 0x{pos:08x}: {text}")
    
    def generate_summary(self):
        """분석 결과 요약"""
        print("\n" + "="*60)
        print("=== 파일 분석 요약 ===")
        print("="*60)
        
        print(f"파일명: {os.path.basename(self.file_path)}")
        print(f"크기: {self.file_size:,} bytes ({self.file_size / 1024 / 1024:.2f} MB)")
        
        # 파일 확장자 기반 추정
        if 'Section_Raw' in self.file_path and '.bin' in self.file_path:
            print("파일 유형: UEFI 펌웨어 섹션 추출 파일")
            print("예상 내용: UEFI 모듈, 드라이버, 또는 설정 데이터")
        
        # 바이트 분포 통계
        byte_counts = defaultdict(int)
        for byte in self.data[:min(10000, len(self.data))]:  # 처음 10KB만 분석
            byte_counts[byte] += 1
        
        most_common = sorted(byte_counts.items(), key=lambda x: x[1], reverse=True)
        print(f"\n가장 많이 나타나는 바이트값 (처음 10KB 기준):")
        for byte_val, count in most_common[:5]:
            percentage = (count / min(10000, len(self.data))) * 100
            print(f"  0x{byte_val:02x} ({byte_val}): {count}회 ({percentage:.1f}%)")
    
    def collect_analysis_data(self):
        """분석 데이터를 수집하여 딕셔너리로 반환"""
        from datetime import datetime
        import math
        
        analysis_data = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'file_info': {
                'filename': os.path.basename(self.file_path),
                'filepath': self.file_path,
                'size_bytes': self.file_size,
                'size_mb': round(self.file_size / 1024 / 1024, 2)
            },
            'magic_bytes': [],
            'magic_pattern_frequency': {},
            'patterns': {},
            'pattern_frequency': {},
            'embedded_files': [],
            'entropy_analysis': {
                'high_entropy': [],
                'low_entropy': []
            },
            'structure_analysis': {
                'null_sequences': [],
                'aligned_blocks': []
            },
            'byte_statistics': {}
        }
        
        # 매직 바이트 분석
        magic_patterns = {
            b'MZ': 'PE/DOS Executable',
            b'PE\x00\x00': 'PE Header',
            b'\x7fELF': 'ELF Binary',
            b'PK\x03\x04': 'ZIP Archive',
            b'\x1f\x8b': 'GZIP',
            b'BM': 'Bitmap Image',
            b'\xff\xd8\xff': 'JPEG Image',
            b'\x89PNG': 'PNG Image',
            b'GIF8': 'GIF Image',
            b'RIFF': 'RIFF Container',
            b'_FVH': 'UEFI Firmware Volume',
            b'$FV$': 'UEFI Firmware Volume Signature'
        }
        
        # 매직 바이트 패턴 빈도 수집
        for magic_bytes, description in magic_patterns.items():
            count = self.data.count(magic_bytes)
            if count > 0:
                analysis_data['magic_pattern_frequency'][binascii.hexlify(magic_bytes).decode()] = {
                    'description': description,
                    'count': count,
                    'frequency_per_mb': round(count / (self.file_size / 1024 / 1024), 2) if self.file_size > 0 else 0
                }
        
        for length in [2, 3, 4, 8, 16]:
            if len(self.data) >= length:
                header = self.data[:length]
                for magic, description in magic_patterns.items():
                    if header.startswith(magic):
                        analysis_data['magic_bytes'].append({
                            'bytes': binascii.hexlify(magic).decode(),
                            'description': description
                        })
        
        # 패턴 분석
        patterns = {
            b'UEFI': 'UEFI 문자열',
            b'BIOS': 'BIOS 문자열',
            b'Award': 'Award BIOS',
            b'AMI': 'AMI BIOS',
            b'Phoenix': 'Phoenix BIOS',
            b'ASUS': 'ASUS 관련',
            b'Intel': 'Intel 관련',
            b'AMD': 'AMD 관련',
            b'\x89PNG': 'PNG 이미지',
            b'\xff\xd8\xff': 'JPEG 이미지',
            b'BM': 'BMP 이미지',
            b'\x00' * 16: '16바이트 NULL 패턴',
            b'\xff' * 16: '16바이트 0xFF 패턴',
            b'GIF8': 'GIF 이미지',
            b'RIFF': 'RIFF 파일',
            b'IEND': 'PNG 종료 마커'
        }
        
        # 패턴 빈도 통계 수집
        for pattern, description in patterns.items():
            count = self.data.count(pattern)
            analysis_data['pattern_frequency'][description] = {
                'pattern_hex': binascii.hexlify(pattern).decode() if len(pattern) <= 16 else binascii.hexlify(pattern[:16]).decode() + '...',
                'count': count,
                'density_per_kb': round(count / (self.file_size / 1024), 3) if self.file_size > 0 else 0,
                'percentage_of_file': round((count * len(pattern) / self.file_size) * 100, 4) if self.file_size > 0 else 0
            }
        
        for pattern, description in patterns.items():
            count = self.data.count(pattern)
            if count > 0:
                positions = []
                start = 0
                for _ in range(min(count, 5)):
                    pos = self.data.find(pattern, start)
                    if pos != -1:
                        positions.append(f"0x{pos:08x}")
                        start = pos + 1
                    else:
                        break
                analysis_data['patterns'][description] = {
                    'count': count,
                    'positions': positions
                }
        
        # 임베디드 파일 분석 (모든 파일 타입을 통합하여 위치 순서대로 정렬)
        embedded_files = []
        
        # PNG 파일 찾기
        png_start = 0
        while True:
            png_pos = self.data.find(b'\x89PNG\r\n\x1a\n', png_start)
            if png_pos == -1:
                break
            
            iend_pos = self.data.find(b'IEND\xaeB`\x82', png_pos)
            if iend_pos != -1:
                png_size = iend_pos + 8 - png_pos
                
                # PNG 세부 정보 추출
                png_info = {
                    'type': 'PNG Image',
                    'start_pos': png_pos,  # 정렬용 숫자 위치
                    'start': f"0x{png_pos:08x}",
                    'end': f"0x{png_pos + png_size:08x}",
                    'size_bytes': png_size,
                    'size_kb': round(png_size / 1024, 1)
                }
                
                # PNG 헤더 정보 추출
                try:
                    ihdr_pos = self.data.find(b'IHDR', png_pos)
                    if ihdr_pos != -1:
                        ihdr_data = self.data[ihdr_pos + 4:ihdr_pos + 17]
                        if len(ihdr_data) >= 13:
                            width, height, bit_depth, color_type = struct.unpack('>IIBBB', ihdr_data[:9])
                            png_info['width'] = width
                            png_info['height'] = height
                            png_info['bit_depth'] = bit_depth
                            png_info['color_type'] = color_type
                except:
                    pass
                
                embedded_files.append(png_info)
            png_start = png_pos + 1
        
        # BMP 파일 분석
        bmp_start = 0
        while True:
            bmp_pos = self.data.find(b'BM', bmp_start)
            if bmp_pos == -1:
                break
            
            if bmp_pos + 6 <= len(self.data):
                try:
                    bmp_size_bytes = self.data[bmp_pos + 2:bmp_pos + 6]
                    bmp_size = struct.unpack('<I', bmp_size_bytes)[0]
                    
                    if 100 <= bmp_size <= 50 * 1024 * 1024 and bmp_pos + bmp_size <= len(self.data):
                        # BMP 세부 정보 추출
                        bmp_info = {
                            'type': 'BMP Image',
                            'start_pos': bmp_pos,  # 정렬용 숫자 위치
                            'start': f"0x{bmp_pos:08x}",
                            'end': f"0x{bmp_pos + bmp_size:08x}",
                            'size_bytes': bmp_size,
                            'size_kb': round(bmp_size / 1024, 1)
                        }
                        
                        # BMP 헤더 정보 추출
                        try:
                            if bmp_pos + 54 <= len(self.data):
                                dib_header_size = struct.unpack('<I', self.data[bmp_pos + 14:bmp_pos + 18])[0]
                                if dib_header_size >= 40:
                                    width = struct.unpack('<i', self.data[bmp_pos + 18:bmp_pos + 22])[0]
                                    height = struct.unpack('<i', self.data[bmp_pos + 22:bmp_pos + 26])[0]
                                    bit_count = struct.unpack('<H', self.data[bmp_pos + 28:bmp_pos + 30])[0]
                                    bmp_info['width'] = abs(width)
                                    bmp_info['height'] = abs(height)
                                    bmp_info['bit_depth'] = bit_count
                        except:
                            pass
                        
                        embedded_files.append(bmp_info)
                except:
                    pass
            bmp_start = bmp_pos + 1
        
        # JPEG 파일 분석
        jpeg_start = 0
        while True:
            jpeg_pos = self.data.find(b'\xff\xd8\xff', jpeg_start)
            if jpeg_pos == -1:
                break
            
            # JPEG 끝 찾기 (FFD9)
            search_pos = jpeg_pos + 3
            jpeg_end = -1
            while search_pos < len(self.data) - 1:
                if self.data[search_pos:search_pos+2] == b'\xff\xd9':
                    jpeg_end = search_pos + 2
                    break
                search_pos += 1
            
            if jpeg_end != -1:
                jpeg_size = jpeg_end - jpeg_pos
                
                # JPEG 세부 정보 추출
                jpeg_info = {
                    'type': 'JPEG Image',
                    'start_pos': jpeg_pos,  # 정렬용 숫자 위치
                    'start': f"0x{jpeg_pos:08x}",
                    'end': f"0x{jpeg_end:08x}",
                    'size_bytes': jpeg_size,
                    'size_kb': round(jpeg_size / 1024, 1)
                }
                
                # JPEG 헤더 정보 추출
                try:
                    # JFIF 헤더 확인
                    if jpeg_pos + 20 <= len(self.data):
                        if b'JFIF' in self.data[jpeg_pos:jpeg_pos+20]:
                            jfif_pos = self.data.find(b'JFIF', jpeg_pos)
                            if jfif_pos != -1 and jfif_pos + 14 <= len(self.data):
                                version_major = self.data[jfif_pos + 5]
                                version_minor = self.data[jfif_pos + 6]
                                units = self.data[jfif_pos + 7]
                                x_density = struct.unpack('>H', self.data[jfif_pos + 8:jfif_pos + 10])[0]
                                y_density = struct.unpack('>H', self.data[jfif_pos + 10:jfif_pos + 12])[0]
                                jpeg_info['jfif_version'] = f"{version_major}.{version_minor}"
                                jpeg_info['density'] = f"{x_density}x{y_density}"
                    
                    # SOF 마커에서 이미지 크기 정보 추출
                    sof_markers = [b'\xff\xc0', b'\xff\xc1', b'\xff\xc2']  # SOF0, SOF1, SOF2
                    for sof_marker in sof_markers:
                        sof_pos = self.data.find(sof_marker, jpeg_pos)
                        if sof_pos != -1 and sof_pos + 9 <= len(self.data):
                            precision = self.data[sof_pos + 4]
                            height = struct.unpack('>H', self.data[sof_pos + 5:sof_pos + 7])[0]
                            width = struct.unpack('>H', self.data[sof_pos + 7:sof_pos + 9])[0]
                            components = self.data[sof_pos + 9]
                            jpeg_info['width'] = width
                            jpeg_info['height'] = height
                            jpeg_info['bit_depth'] = precision
                            jpeg_info['components'] = components
                            break
                except:
                    pass
                
                embedded_files.append(jpeg_info)
            jpeg_start = jpeg_pos + 1
        
        # 모든 임베디드 파일을 위치 순서대로 정렬
        embedded_files.sort(key=lambda x: x['start_pos'])
        
        # start_pos 필드 제거 (정렬에만 사용)
        for file_info in embedded_files:
            del file_info['start_pos']
        
        analysis_data['embedded_files'] = embedded_files
        
        # 엔트로피 분석
        block_size = 1024
        for i in range(0, len(self.data), block_size):
            block = self.data[i:i+block_size]
            if len(block) < block_size // 2:
                continue
                
            byte_counts = defaultdict(int)
            for byte in block:
                byte_counts[byte] += 1
            
            entropy = 0
            for count in byte_counts.values():
                p = count / len(block)
                if p > 0:
                    entropy -= p * math.log2(p)
            
            if entropy > 7.5:
                analysis_data['entropy_analysis']['high_entropy'].append({
                    'offset': f"0x{i:08x}",
                    'entropy': round(entropy, 2)
                })
            elif entropy < 2.0:
                analysis_data['entropy_analysis']['low_entropy'].append({
                    'offset': f"0x{i:08x}",
                    'entropy': round(entropy, 2)
                })
        
        # 구조 분석 - NULL 시퀀스
        null_sequences = []
        i = 0
        while i < len(self.data) - 4:
            if self.data[i:i+4] == b'\x00\x00\x00\x00':
                start = i
                while i < len(self.data) and self.data[i] == 0:
                    i += 1
                null_sequences.append({
                    'offset': f"0x{start:08x}",
                    'length': i - start
                })
            else:
                i += 1
        analysis_data['structure_analysis']['null_sequences'] = null_sequences[:10]
        
        # 바이트 통계
        byte_counts = defaultdict(int)
        for byte in self.data[:min(10000, len(self.data))]:
            byte_counts[byte] += 1
        
        most_common = sorted(byte_counts.items(), key=lambda x: x[1], reverse=True)
        for byte_val, count in most_common[:5]:
            percentage = (count / min(10000, len(self.data))) * 100
            analysis_data['byte_statistics'][f"0x{byte_val:02x}"] = {
                'count': count,
                'percentage': round(percentage, 1)
            }
        
        return analysis_data
    
    def save_analysis_results_txt(self, output_file=None):
        """분석 결과를 TXT 파일로 저장"""
        if output_file is None:
            base_name = os.path.splitext(self.file_path)[0]
            output_file = f"{base_name}_analysis.txt"
        
        try:
            analysis_data = self.collect_analysis_data()
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("="*80 + "\n")
                f.write("바이너리 파일 분석 보고서\n")
                f.write("="*80 + "\n\n")
                
                # 기본 정보
                f.write(f"분석 일시: {analysis_data['timestamp']}\n")
                f.write(f"파일명: {analysis_data['file_info']['filename']}\n")
                f.write(f"파일 경로: {analysis_data['file_info']['filepath']}\n")
                f.write(f"파일 크기: {analysis_data['file_info']['size_bytes']:,} bytes ({analysis_data['file_info']['size_mb']} MB)\n\n")
                
                # 매직 바이트
                if analysis_data['magic_bytes']:
                    f.write("매직 바이트 분석\n")
                    f.write("-" * 40 + "\n")
                    for magic in analysis_data['magic_bytes']:
                        f.write(f"  {magic['bytes']}: {magic['description']}\n")
                    f.write("\n")
                
                # 매직 패턴 빈도
                if analysis_data['magic_pattern_frequency']:
                    f.write("매직 패턴 빈도 분석\n")
                    f.write("-" * 40 + "\n")
                    for pattern_hex, info in analysis_data['magic_pattern_frequency'].items():
                        f.write(f"  {pattern_hex} ({info['description']}): {info['count']}개 ({info['frequency_per_mb']}/MB)\n")
                    f.write("\n")
                
                # 패턴 분석
                if analysis_data['patterns']:
                    f.write("패턴 분석\n")
                    f.write("-" * 40 + "\n")
                    for pattern, info in analysis_data['patterns'].items():
                        f.write(f"  {pattern}: {info['count']}개 발견\n")
                        f.write(f"    위치: {', '.join(info['positions'])}\n")
                        if info['count'] > 5:
                            f.write(f"    (총 {info['count']}개, 처음 5개만 표시)\n")
                    f.write("\n")
                
                # 패턴 빈도 통계
                if analysis_data['pattern_frequency']:
                    f.write("패턴 빈도 통계\n")
                    f.write("-" * 40 + "\n")
                    f.write("패턴                  | 개수      | 밀도(/KB) | 비율(%)\n")
                    f.write("-" * 60 + "\n")
                    for description, info in analysis_data['pattern_frequency'].items():
                        if info['count'] > 0:  # 발견된 패턴만 표시
                            f.write(f"{description:<20} | {info['count']:>8} | {info['density_per_kb']:>8} | {info['percentage_of_file']:>6}\n")
                    f.write("\n")
                
                # 임베디드 파일
                if analysis_data['embedded_files']:
                    f.write("임베디드 파일 분석\n")
                    f.write("-" * 40 + "\n")
                    for i, file_info in enumerate(analysis_data['embedded_files'], 1):
                        f.write(f"  {i}. {file_info['type']}\n")
                        f.write(f"     위치: {file_info['start']} - {file_info['end']}\n")
                        f.write(f"     크기: {file_info['size_bytes']:,} bytes ({file_info['size_kb']} KB)\n")
                        if 'width' in file_info:
                            if file_info['type'] == 'JPEG Image':
                                f.write(f"     이미지 정보: {file_info['width']}x{file_info['height']}, {file_info['bit_depth']}bit, {file_info.get('components', 'N/A')}컴포넌트\n")
                                if 'jfif_version' in file_info:
                                    f.write(f"     JFIF v{file_info['jfif_version']}, 밀도: {file_info.get('density', 'N/A')} DPI\n")
                            else:
                                f.write(f"     이미지 정보: {file_info['width']}x{file_info['height']}, {file_info['bit_depth']}bit\n")
                    f.write("\n")
                
                # 엔트로피 분석
                f.write("엔트로피 분석\n")
                f.write("-" * 40 + "\n")
                if analysis_data['entropy_analysis']['high_entropy']:
                    f.write("높은 엔트로피 영역 (압축/암호화 가능성):\n")
                    for entry in analysis_data['entropy_analysis']['high_entropy'][:10]:
                        f.write(f"  오프셋 {entry['offset']}: 엔트로피 {entry['entropy']}\n")
                
                if analysis_data['entropy_analysis']['low_entropy']:
                    f.write("낮은 엔트로피 영역 (반복 패턴/빈 공간):\n")
                    for entry in analysis_data['entropy_analysis']['low_entropy'][:10]:
                        f.write(f"  오프셋 {entry['offset']}: 엔트로피 {entry['entropy']}\n")
                f.write("\n")
                
                # 구조 분석
                if analysis_data['structure_analysis']['null_sequences']:
                    f.write("구조 분석\n")
                    f.write("-" * 40 + "\n")
                    f.write("NULL 바이트 시퀀스 (패딩/정렬 가능성):\n")
                    for seq in analysis_data['structure_analysis']['null_sequences']:
                        f.write(f"  오프셋 {seq['offset']}: {seq['length']}바이트\n")
                    f.write("\n")
                
                # 바이트 통계
                if analysis_data['byte_statistics']:
                    f.write("바이트 통계 (처음 10KB 기준)\n")
                    f.write("-" * 40 + "\n")
                    for byte_val, stats in analysis_data['byte_statistics'].items():
                        f.write(f"  {byte_val}: {stats['count']}회 ({stats['percentage']}%)\n")
                
                f.write("\n" + "="*80 + "\n")
                f.write("분석 완료\n")
                f.write("="*80 + "\n")
            
            print(f"✓ TXT 분석 보고서 저장 완료: {output_file}")
            return True
            
        except Exception as e:
            print(f"✗ TXT 보고서 저장 실패: {e}")
            return False
    
    def save_analysis_results_md(self, output_file=None):
        """분석 결과를 마크다운 파일로 저장 (원본 파일과 같은 디렉터리에 생성)"""
        if output_file is None:
            # 원본 파일의 디렉터리와 파일명 분리
            original_dir = os.path.dirname(self.file_path)
            original_name = os.path.splitext(os.path.basename(self.file_path))[0]
            
            # 원본 파일 디렉터리에 MD 파일 생성
            output_file = os.path.join(original_dir, f"{original_name}_analysis.md")
        
        try:
            analysis_data = self.collect_analysis_data()
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("# 바이너리 파일 분석 보고서\n\n")
                
                # 기본 정보
                f.write("## 📋 기본 정보\n\n")
                f.write(f"- **분석 일시**: {analysis_data['timestamp']}\n")
                f.write(f"- **파일명**: `{analysis_data['file_info']['filename']}`\n")
                f.write(f"- **파일 경로**: `{analysis_data['file_info']['filepath']}`\n")
                f.write(f"- **파일 크기**: {analysis_data['file_info']['size_bytes']:,} bytes ({analysis_data['file_info']['size_mb']} MB)\n\n")
                
                # 매직 바이트
                if analysis_data['magic_bytes']:
                    f.write("## 🔍 매직 바이트 분석\n\n")
                    f.write("| 바이트 | 설명 |\n")
                    f.write("|--------|------|\n")
                    for magic in analysis_data['magic_bytes']:
                        f.write(f"| `{magic['bytes']}` | {magic['description']} |\n")
                    f.write("\n")
                
                # 매직 패턴 빈도
                if analysis_data['magic_pattern_frequency']:
                    f.write("## 📊 매직 패턴 빈도 분석\n\n")
                    f.write("> 📝 **Note**: 임베디드 파일을 구성하는 바이너리 내에도 매직 패턴 또는 패턴들이 포함될 수 있어, 정확하지 않을 수 있습니다.\n\n")
                    f.write("| 패턴 | 설명 | 개수 | 빈도(/MB) |\n")
                    f.write("|------|------|------|----------|\n")
                    for pattern_hex, info in analysis_data['magic_pattern_frequency'].items():
                        f.write(f"| `{pattern_hex}` | {info['description']} | {info['count']} | {info['frequency_per_mb']} |\n")
                    f.write("\n")
                
                # 패턴 분석
                if analysis_data['patterns']:
                    f.write("## 🔎 패턴 분석\n\n")
                    f.write("> 📝 **Note**: 임베디드 파일을 구성하는 바이너리 내에도 매직 패턴 또는 패턴들이 포함될 수 있어, 정확하지 않을 수 있습니다.\n\n")
                    f.write("| 패턴 | 개수 | 위치 |\n")
                    f.write("|------|------|------|\n")
                    for pattern, info in analysis_data['patterns'].items():
                        positions = ', '.join(info['positions'])
                        if info['count'] > 5:
                            positions += f" (총 {info['count']}개)"
                        f.write(f"| {pattern} | {info['count']} | `{positions}` |\n")
                    f.write("\n")
                
                # 패턴 빈도 통계
                if analysis_data['pattern_frequency']:
                    f.write("## 📈 패턴 빈도 통계\n\n")
                    f.write("> 📝 **Note**: 임베디드 파일을 구성하는 바이너리 내에도 매직 패턴 또는 패턴들이 포함될 수 있어, 정확하지 않을 수 있습니다.\n\n")
                    f.write("| 패턴 | 개수 | 밀도(/KB) | 파일 비율(%) |\n")
                    f.write("|------|------|-----------|-------------|\n")
                    for description, info in analysis_data['pattern_frequency'].items():
                        if info['count'] > 0:  # 발견된 패턴만 표시
                            f.write(f"| {description} | {info['count']} | {info['density_per_kb']} | {info['percentage_of_file']} |\n")
                    f.write("\n")
                
                # 임베디드 파일
                if analysis_data['embedded_files']:
                    f.write("## 🖼️ 임베디드 파일 분석\n\n")
                    f.write(f"총 **{len(analysis_data['embedded_files'])}개**의 임베디드 파일이 발견되었습니다.\n\n")
                    
                    f.write("| # | 타입 | 위치 | 크기 | 세부정보 |\n")
                    f.write("|---|------|------|------|----------|\n")
                    for i, file_info in enumerate(analysis_data['embedded_files'], 1):
                        details = ""
                        if 'width' in file_info:
                            if file_info['type'] == 'JPEG Image':
                                if 'jfif_version' in file_info and 'density' in file_info:
                                    details = f"{file_info['width']}×{file_info['height']}, {file_info['bit_depth']}bit, {file_info['components']}컴포넌트, JFIF v{file_info['jfif_version']}"
                                else:
                                    details = f"{file_info['width']}×{file_info['height']}, {file_info['bit_depth']}bit, {file_info.get('components', 'N/A')}컴포넌트"
                            else:
                                details = f"{file_info['width']}×{file_info['height']}, {file_info['bit_depth']}bit"
                        f.write(f"| {i} | {file_info['type']} | `{file_info['start']} - {file_info['end']}` | {file_info['size_bytes']:,} bytes ({file_info['size_kb']} KB) | {details} |\n")
                    f.write("\n")
                
                # 엔트로피 분석
                f.write("## 📊 엔트로피 분석\n\n")
                
                if analysis_data['entropy_analysis']['high_entropy']:
                    f.write("### 🔴 높은 엔트로피 영역 (압축/암호화 가능성)\n\n")
                    f.write("| 오프셋 | 엔트로피 |\n")
                    f.write("|--------|----------|\n")
                    for entry in analysis_data['entropy_analysis']['high_entropy'][:10]:
                        f.write(f"| `{entry['offset']}` | {entry['entropy']} |\n")
                    f.write("\n")
                
                if analysis_data['entropy_analysis']['low_entropy']:
                    f.write("### 🟢 낮은 엔트로피 영역 (반복 패턴/빈 공간)\n\n")
                    f.write("| 오프셋 | 엔트로피 |\n")
                    f.write("|--------|----------|\n")
                    for entry in analysis_data['entropy_analysis']['low_entropy'][:10]:
                        f.write(f"| `{entry['offset']}` | {entry['entropy']} |\n")
                    f.write("\n")
                
                # 구조 분석
                if analysis_data['structure_analysis']['null_sequences']:
                    f.write("## 🏗️ 구조 분석\n\n")
                    f.write("### NULL 바이트 시퀀스 (패딩/정렬 가능성)\n\n")
                    f.write("| 오프셋 | 길이 |\n")
                    f.write("|--------|------|\n")
                    for seq in analysis_data['structure_analysis']['null_sequences']:
                        f.write(f"| `{seq['offset']}` | {seq['length']} bytes |\n")
                    f.write("\n")
                
                # 바이트 통계
                if analysis_data['byte_statistics']:
                    f.write("## 📈 바이트 통계 (처음 10KB 기준)\n\n")
                    f.write("| 바이트 값 | 개수 | 비율 |\n")
                    f.write("|-----------|------|------|\n")
                    for byte_val, stats in analysis_data['byte_statistics'].items():
                        f.write(f"| `{byte_val}` | {stats['count']} | {stats['percentage']}% |\n")
                    f.write("\n")
                
                # 요약
                f.write("## 📝 분석 요약\n\n")
                
                if 'Section_Raw' in analysis_data['file_info']['filepath'] and '.bin' in analysis_data['file_info']['filepath']:
                    f.write("- **파일 유형**: UEFI 펌웨어 섹션 추출 파일\n")
                    f.write("- **예상 내용**: UEFI 모듈, 드라이버, 또는 설정 데이터\n")
                
                if analysis_data['embedded_files']:
                    total_images = len(analysis_data['embedded_files'])
                    f.write(f"- **임베디드 이미지**: {total_images}개 발견\n")
                
                if analysis_data['patterns']:
                    f.write(f"- **발견된 패턴**: {len(analysis_data['patterns'])}가지\n")
                
                f.write(f"- **분석 완료 시점**: {analysis_data['timestamp']}\n\n")
                
                f.write("---\n\n")
                f.write("*이 보고서는 바이너리 파일 분석 도구에 의해 자동 생성되었습니다.*\n")
            
            print(f"✓ 마크다운 분석 보고서 저장 완료: {output_file}")
            return True
            
        except Exception as e:
            print(f"✗ 마크다운 보고서 저장 실패: {e}")
            return False
    
    def run_full_analysis(self):
        """전체 분석 실행"""
        print("바이너리 파일 분석을 시작합니다...")
        print("="*60)
        
        self.load_file()
        self.analyze_magic_bytes()
        self.find_patterns()
        self.analyze_embedded_files()
        self.analyze_entropy()
        self.analyze_structure()
        self.generate_summary()
        
        # 분석 완료 후 보고서 저장
        print("\n" + "="*60)
        print("=== 분석 보고서 저장 ===")
        print("="*60)
        
        # TXT 보고서 저장
        txt_success = self.save_analysis_results_txt()
        
        # 마크다운 보고서 저장
        md_success = self.save_analysis_results_md()
        
        if txt_success and md_success:
            print("📄 모든 분석 보고서가 성공적으로 저장되었습니다!")
        elif txt_success or md_success:
            print("⚠️ 일부 분석 보고서만 저장되었습니다.")
        else:
            print("❌ 분석 보고서 저장에 실패했습니다.")
        
        # 저장된 파일 위치 안내
        base_name = os.path.splitext(self.file_path)[0]
        print(f"\n📁 보고서 저장 위치:")
        print(f"   TXT: {base_name}_analysis.txt")
        print(f"   MD:  {base_name}_analysis.md")