"""
MSI BIOS 파일 분석기

MSI 메인보드의 BIOS/UEFI Section 바이너리 파일을 분석하여
MSI Packer 구조와 임베디드 이미지들을 분석합니다.
분석 전용 도구로 추출 기능은 포함되지 않습니다.
"""

import os
import sys
import struct
import binascii
from typing import List, Dict, Any, NamedTuple, Optional
from collections import OrderedDict
from datetime import datetime

# Windows 한글 출력 지원
if os.name == 'nt':  # Windows
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except:
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.detach())


class MSIHeader(NamedTuple):
    """MSI 헤더 구조체 (12 bytes)"""
    signature: bytes      # 0x00-0x03: b'$MsI$' (4 bytes)
    sector: int          # 0x04: Sector/Layer field (1 byte)
    layer: int           # 0x05: Layer/Position field (1 byte) 
    image_number: int    # 0x06: Image sequence number (1 byte)
    reserved: int        # 0x07: Reserved field (1 byte)
    image_size: int      # 0x08-0x0B: Image data size in bytes (4 bytes, little-endian)


class MSIFileAnalyzer:
    """MSI BIOS 파일 분석기 (분석 전용, 추출 기능 제외)"""
    
    def __init__(self):
        """초기화"""
        self.MSI_SIGNATURE = b'$MsI$'
        self.HEADER_SIZE = 12
        
        # 매직 바이트 패턴 정의
        self.magic_patterns = {
            b'$MsI$': 'MSI Packer Header',
            b'\xFF\xD8\xFF': 'JPEG Image Start',
            b'\x89\x50\x4E\x47': 'PNG Image Start', 
            b'BM': 'BMP Image Start',
            b'\x00\x00\x01\x00': 'ICO Image Start',
            b'RIFF': 'RIFF Container',
            b'MZ': 'PE/DOS Executable',
            b'_FVH': 'UEFI Firmware Volume'
        }
        
        # 분석 결과 저장
        self.analysis_results = {}
        
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """MSI 바이너리 파일 분석"""
        try:
            print(f"\n=== MSI BIOS 파일 분석 시작 ===")
            print(f"분석할 파일: {os.path.basename(file_path)}")
            
            # 파일 읽기
            with open(file_path, 'rb') as f:
                data = f.read()
            
            file_size = len(data)
            print(f"파일 크기: {file_size:,} bytes ({file_size/1024:.2f} KB)")
            
            # 기본 정보 수집
            results = {
                'file_path': file_path,
                'file_size': file_size,
                'timestamp': datetime.now().isoformat(),
                'magic_bytes': [],
                'msi_entries': [],
                'summary': {}
            }
            
            # 매직 바이트 검색
            print(f"\n=== 매직 바이트 분석 ===")
            magic_bytes = self._find_magic_bytes(data)
            results['magic_bytes'] = magic_bytes
            
            # MSI 시그니처 개수 확인
            msi_signature_count = data.count(self.MSI_SIGNATURE)
            print(f"MSI 시그니처 '$MsI$' 발견 개수: {msi_signature_count}개")
            
            # MSI 엔트리 검색 및 분석
            print(f"\n=== MSI Packer 엔트리 분석 ===")
            if msi_signature_count == 0:
                print("[WARNING] MSI Packer 시그니처를 찾을 수 없습니다.")
                print("이 파일은 MSI Packer 형식이 아닐 수 있습니다.")
                print("파일의 처음 64바이트를 확인합니다...")
                hex_dump = ' '.join(f'{b:02X}' for b in data[:64])
                print(f"첫 64바이트: {hex_dump}")
                
                # 다른 가능한 시그니처들 확인
                print("\n다른 알려진 패턴 검색 중...")
                for pattern, desc in self.magic_patterns.items():
                    if pattern in data:
                        first_pos = data.find(pattern)
                        print(f"  - {desc}: 0x{first_pos:08X}에서 발견")
                        
                print("\n이 파일을 분석하려면 올바른 MSI BIOS Section 파일이 필요합니다.")
            
            msi_entries = self._find_msi_entries(data)
            results['msi_entries'] = msi_entries
            
            if not msi_entries:
                print("\n[INFO] 표준 MSI Packer 엔트리를 찾을 수 없습니다.")
                print("대안 분석을 시도합니다...")
                
                # 대안 1: 알려진 이미지 시그니처 기반 분석  
                image_entries = self._find_embedded_images(data)
                if image_entries:
                    print(f"[INFO] 임베디드 이미지 {len(image_entries)}개를 발견했습니다.")
                    results['embedded_images'] = image_entries
                else:
                    print("[WARNING] 이미지 데이터를 찾을 수 없습니다.")
                    
                # 대안 2: 파일 형식 추정
                file_type = self._guess_file_format(data)
                print(f"[INFO] 추정 파일 형식: {file_type}")
                results['guessed_format'] = file_type
            else:
                print(f"\n[SUCCESS] {len(msi_entries)}개의 MSI 엔트리를 발견했습니다.")
            
            # 통계 생성
            summary = self._generate_summary(results)
            results['summary'] = summary
            
            # 결과 출력
            self._print_analysis_results(results)
            
            self.analysis_results = results
            return results
            
        except Exception as e:
            print(f"[ERROR] 파일 분석 중 오류 발생: {e}")
            return {}
    
    def _find_magic_bytes(self, data: bytes) -> List[Dict[str, Any]]:
        """매직 바이트 패턴 검색"""
        magic_bytes = []
        
        for pattern, description in self.magic_patterns.items():
            offset = 0
            while True:
                pos = data.find(pattern, offset)
                if pos == -1:
                    break
                    
                magic_info = {
                    'offset': pos,
                    'pattern': pattern.hex().upper(),
                    'description': description,
                    'ascii': self._bytes_to_ascii(pattern)
                }
                magic_bytes.append(magic_info)
                print(f"오프셋 0x{pos:08X}: {pattern.hex().upper()} ({description})")
                
                offset = pos + 1
        
        return magic_bytes
    
    def _find_msi_entries(self, data: bytes) -> List[Dict[str, Any]]:
        """MSI 엔트리 검색 및 분석"""
        entries = []
        offset = 0
        
        while offset < len(data) - self.HEADER_SIZE:
            if data[offset:offset+4] == self.MSI_SIGNATURE:
                try:
                    # MSI 헤더 파싱
                    header = self._parse_msi_header(data, offset)
                    
                    # 이미지 데이터 추출
                    image_start = offset + self.HEADER_SIZE
                    image_end = image_start + header.image_size
                    
                    if image_end <= len(data):
                        image_data = data[image_start:image_end]
                        
                        entry = {
                            'index': len(entries),
                            'offset': offset,
                            'header': header._asdict(),
                            'image_data_offset': image_start,
                            'image_data_size': header.image_size,
                            'image_type': self._detect_image_type(image_data),
                            'image_preview': image_data[:32].hex().upper() if len(image_data) >= 32 else image_data.hex().upper()
                        }
                        entries.append(entry)
                        
                        print(f"MSI Entry #{len(entries)-1}: 오프셋 0x{offset:08X}, 크기 {header.image_size:,} bytes, 타입: {entry['image_type']}")
                        
                        # 다음 엔트리로 점프
                        offset = image_end
                    else:
                        offset += 1
                        
                except Exception as e:
                    print(f"[WARNING] 오프셋 0x{offset:08X}에서 MSI 헤더 파싱 실패: {e}")
                    offset += 1
            else:
                offset += 1
        
        return entries
    
    def _parse_msi_header(self, data: bytes, offset: int) -> MSIHeader:
        """MSI 헤더 파싱"""
        if offset + self.HEADER_SIZE > len(data):
            raise ValueError(f"오프셋 {offset:#x}에서 헤더를 읽을 수 없습니다")
            
        header_data = data[offset:offset + self.HEADER_SIZE]
        
        # 바이너리 언패킹
        signature = header_data[0:4]
        sector = header_data[4]
        layer = header_data[5] 
        image_number = header_data[6]
        reserved = header_data[7]
        image_size = struct.unpack('<I', header_data[8:12])[0]  # Little-endian
        
        return MSIHeader(signature, sector, layer, image_number, reserved, image_size)
    
    def _detect_image_type(self, image_data: bytes) -> str:
        """이미지 타입 감지"""
        if not image_data:
            return "Empty"
        
        # 매직 바이트로 이미지 타입 감지
        for magic, desc in self.magic_patterns.items():
            if image_data.startswith(magic):
                return desc
        
        # 추가 분석
        if len(image_data) >= 4:
            first_bytes = image_data[:4]
            return f"Unknown (시작: {first_bytes.hex().upper()})"
        
        return "Unknown"
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """분석 결과 요약 생성"""
        entries = results['msi_entries']
        
        # 이미지 타입별 통계
        type_stats = {}
        total_image_size = 0
        
        for entry in entries:
            img_type = entry['image_type']
            size = entry['image_data_size']
            
            if img_type not in type_stats:
                type_stats[img_type] = {'count': 0, 'total_size': 0}
            
            type_stats[img_type]['count'] += 1
            type_stats[img_type]['total_size'] += size
            total_image_size += size
        
        # 요약 정보
        summary = {
            'total_entries': len(entries),
            'total_image_size': total_image_size,
            'image_type_stats': type_stats,
            'magic_byte_count': len(results['magic_bytes']),
            'file_coverage': (total_image_size / results['file_size'] * 100) if results['file_size'] > 0 else 0
        }
        
        return summary
    
    def _print_analysis_results(self, results: Dict[str, Any]):
        """분석 결과 출력"""
        summary = results['summary']
        
        print(f"\n=== 분석 결과 요약 ===")
        print(f"총 MSI 엔트리: {summary['total_entries']}개")
        print(f"총 이미지 크기: {summary['total_image_size']:,} bytes")
        print(f"파일 커버리지: {summary['file_coverage']:.1f}%")
        print(f"매직 바이트 패턴: {summary['magic_byte_count']}개 발견")
        
        print(f"\n=== 이미지 타입별 통계 ===")
        for img_type, stats in summary['image_type_stats'].items():
            count = stats['count']
            size = stats['total_size']
            percentage = (size / summary['total_image_size'] * 100) if summary['total_image_size'] > 0 else 0
            print(f"{img_type}: {count}개, {size:,} bytes ({percentage:.1f}%)")
    
    def _bytes_to_ascii(self, data: bytes) -> str:
        """바이트를 ASCII 문자열로 변환 (출력 가능한 문자만)"""
        return ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)

    def _find_embedded_images(self, data: bytes) -> List[Dict[str, Any]]:
        """임베디드 이미지 검색 (MSI Packer가 아닌 경우의 대안)"""
        images = []
        image_patterns = {
            b'\xFF\xD8\xFF': 'JPEG',
            b'\x89\x50\x4E\x47': 'PNG', 
            b'BM': 'BMP',
            b'\x00\x00\x01\x00': 'ICO'
        }
        
        for pattern, img_type in image_patterns.items():
            offset = 0
            while True:
                pos = data.find(pattern, offset)
                if pos == -1:
                    break
                    
                # 이미지 크기 추정 (간단한 휴리스틱)
                estimated_size = min(1024 * 1024, len(data) - pos)  # 최대 1MB
                
                image_info = {
                    'type': img_type,
                    'offset': pos,
                    'estimated_size': estimated_size,
                    'data_preview': data[pos:pos+32].hex().upper()
                }
                images.append(image_info)
                print(f"  - {img_type} 이미지: 오프셋 0x{pos:08X}")
                
                offset = pos + len(pattern)
                
        return images

    def _guess_file_format(self, data: bytes) -> str:
        """파일 형식 추정"""
        if len(data) < 16:
            return "파일이 너무 작음"
            
        # 시작 바이트 확인
        start_bytes = data[:16]
        
        if b'_FVH' in start_bytes:
            return "UEFI Firmware Volume"
        elif b'MZ' in start_bytes:
            return "PE/DOS Executable"
        elif b'RIFF' in start_bytes:
            return "RIFF Container"
        elif b'\xFF\xD8\xFF' in start_bytes:
            return "JPEG Image"
        elif b'\x89PNG' in start_bytes:
            return "PNG Image"
        elif start_bytes.startswith(b'PK'):
            return "ZIP Archive"
        else:
            return "알 수 없는 형식"
    
    def export_analysis_report(self, output_path: str) -> bool:
        """분석 결과를 텍스트 파일로 내보내기"""
        try:
            if not self.analysis_results:
                print("[ERROR] 분석 결과가 없습니다. 먼저 analyze_file()을 실행하세요.")
                return False
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("=== MSI BIOS 파일 분석 리포트 ===\n")
                f.write(f"생성 시간: {self.analysis_results['timestamp']}\n")
                f.write(f"분석 파일: {self.analysis_results['file_path']}\n")
                f.write(f"파일 크기: {self.analysis_results['file_size']:,} bytes\n\n")
                
                # 매직 바이트 정보
                f.write("=== 매직 바이트 패턴 ===\n")
                for magic in self.analysis_results['magic_bytes']:
                    f.write(f"오프셋 0x{magic['offset']:08X}: {magic['pattern']} ({magic['description']})\n")
                f.write("\n")
                
                # MSI 엔트리 정보
                f.write("=== MSI Packer 엔트리 ===\n")
                for entry in self.analysis_results['msi_entries']:
                    f.write(f"Entry #{entry['index']}:\n")
                    f.write(f"  오프셋: 0x{entry['offset']:08X}\n")
                    f.write(f"  이미지 크기: {entry['image_data_size']:,} bytes\n")
                    f.write(f"  이미지 타입: {entry['image_type']}\n")
                    f.write(f"  이미지 번호: {entry['header']['image_number']}\n")
                    f.write(f"  섹터: 0x{entry['header']['sector']:02X}\n")
                    f.write(f"  레이어: 0x{entry['header']['layer']:02X}\n")
                    f.write(f"  프리뷰: {entry['image_preview']}\n\n")
                
                # 요약 정보
                summary = self.analysis_results['summary']
                f.write("=== 분석 요약 ===\n")
                f.write(f"총 MSI 엔트리: {summary['total_entries']}개\n")
                f.write(f"총 이미지 크기: {summary['total_image_size']:,} bytes\n")
                f.write(f"파일 커버리지: {summary['file_coverage']:.1f}%\n\n")
                
                f.write("=== 이미지 타입별 통계 ===\n")
                for img_type, stats in summary['image_type_stats'].items():
                    count = stats['count']
                    size = stats['total_size']
                    percentage = (size / summary['total_image_size'] * 100) if summary['total_image_size'] > 0 else 0
                    f.write(f"{img_type}: {count}개, {size:,} bytes ({percentage:.1f}%)\n")
            
            print(f"[SUCCESS] 분석 리포트가 저장되었습니다: {output_path}")
            return True
            
        except Exception as e:
            print(f"[ERROR] 리포트 저장 중 오류 발생: {e}")
            return False

if __name__ == "__main__":
    # 테스트 코드
    analyzer = MSIFileAnalyzer()
    
    # 테스트 파일 경로 (실제 사용시 수정 필요)
    test_file = r"C:\OtherProgram\bios_edit3\file_from_uefitool\b850_tomahwak\ext\Section_Raw_004D5349-2400-0000-55AA-55AA55AA55AA_MAG_Common_1920x1080.bin_body.bin"
    
    if os.path.exists(test_file):
        print("MSI 파일 분석기 테스트")
        print("=" * 50)
        
        # 파일 분석
        results = analyzer.analyze_file(test_file)
        
        if results:
            # 리포트 저장
            report_path = "msi_analysis_report.txt"
            analyzer.export_analysis_report(report_path)
            
    else:
        print("테스트 파일을 찾을 수 없습니다.")
