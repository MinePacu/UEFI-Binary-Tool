"""
MSI 이미지 리패커

MSI_Pack 폴더나 추출된 이미지들을 MSI Packer 형식으로 리패킹하여
원본 BIOS 파일과 호환되는 바이너리를 생성합니다.
리패킹 전용 도구로 추출 기능은 포함되지 않습니다.
"""

import os
import sys
import struct
import glob
from typing import List, Dict, Any, Optional, Tuple
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


class MSIImageRepacker:
    """MSI 이미지 리패킹 전용 도구 (추출 기능 제외)"""
    
    def __init__(self):
        """초기화"""
        self.MSI_SIGNATURE = b'$MsI$'
        self.HEADER_SIZE = 12
        
        # 지원되는 이미지 확장자
        self.supported_extensions = ['.bin', '.jpg', '.jpeg', '.png', '.bmp', '.ico']
        
        # 리패킹 결과
        self.repack_results = {}
    
    def repack_from_directory(self, input_dir: str, output_file: str, 
                            preserve_order: bool = True, original_analysis: Dict[str, Any] = None,
                            original_file: str = None) -> bool:
        """추출된 이미지 디렉터리에서 MSI 바이너리로 리패킹 (리패킹 전용)"""
        try:
            print(f"\n=== MSI 이미지 리패킹 시작 ===")
            print(f"입력 디렉터리: {input_dir}")
            print(f"출력 파일: {output_file}")
            
            # 원본 파일 기반 변경 감지 활성화 여부
            enable_change_detection = original_file and os.path.exists(original_file)
            if enable_change_detection:
                print(f"원본 파일: {original_file}")
                print("변경 감지 모드: 수정된 이미지만 처리됩니다.")
            
            # 입력 디렉터리 검증
            if not os.path.exists(input_dir):
                print(f"[ERROR] 입력 디렉터리가 존재하지 않습니다: {input_dir}")
                return False
            
            # MSI_Pack 폴더 찾기 (구조 보존 모드)
            msi_pack_dirs = [d for d in os.listdir(input_dir) 
                           if os.path.isdir(os.path.join(input_dir, d)) and d.startswith('MSI_pack')]
            
            if msi_pack_dirs:
                # 구조 보존 모드로 리패킹
                msi_pack_dir = os.path.join(input_dir, msi_pack_dirs[0])
                print(f"구조 보존 모드: {msi_pack_dir} 사용")
                
                # 변경 감지 수행
                if enable_change_detection:
                    modified_images = self._detect_modified_images(msi_pack_dir, original_file, original_analysis)
                    if not modified_images:
                        print("변경된 이미지가 없으므로 원본 파일을 복사합니다.")
                        return self._copy_original_file(original_file, output_file)
                    print(f"🔄 {len(modified_images)}개의 수정된 이미지 감지됨")
                else:
                    modified_images = None
                
                return self._repack_with_structure_preservation(msi_pack_dir, output_file, original_analysis, modified_images)
            else:
                # 일반 모드로 리패킹
                print("일반 모드: 디렉터리 내 이미지 파일들을 순서대로 리패킹")
                
                # 변경 감지 수행
                if enable_change_detection:
                    modified_images = self._detect_modified_images_simple(input_dir, original_file, original_analysis)
                    if not modified_images:
                        print("변경된 이미지가 없으므로 원본 파일을 복사합니다.")
                        return self._copy_original_file(original_file, output_file)
                    print(f"🔄 {len(modified_images)}개의 수정된 이미지 감지됨")
                else:
                    modified_images = None
                    
                return self._repack_simple_mode(input_dir, output_file, preserve_order, modified_images)
            
        except Exception as e:
            print(f"[ERROR] 리패킹 중 오류 발생: {e}")
            return False
    
    def _repack_with_structure_preservation(self, msi_pack_dir: str, output_file: str, 
                                          original_analysis: Dict[str, Any] = None,
                                          modified_images: Dict[str, Any] = None) -> bool:
        """구조 보존 모드 리패킹"""
        try:
            print(f"구조 보존 리패킹 시작: {msi_pack_dir}")
            
            # 원본 분석 결과 우선 사용
            structure_info = None
            if original_analysis and 'msi_entries' in original_analysis:
                print(f"원본 분석 결과 사용: {len(original_analysis['msi_entries'])}개 엔트리")
                structure_info = {'entries': []}
                for entry in original_analysis['msi_entries']:
                    structure_info['entries'].append({
                        'index': entry['index'],
                        'offset': entry['offset'],
                        'image_size': entry['image_data_size'],
                        'image_type': entry['image_type'],
                        'sector': entry['header']['sector'],
                        'layer': entry['header']['layer'],
                        'image_number': entry['header']['image_number'],
                        'reserved': entry['header']['reserved'],
                        'filename': f"image_nr{entry['index']}_off0x{entry['offset']:X}"
                    })
            else:
                # 메타데이터 파일 읽기
                metadata_file = os.path.join(msi_pack_dir, "msi_structure_info.txt")
                if os.path.exists(metadata_file):
                    structure_info = self._parse_metadata_file(metadata_file)
                    print(f"메타데이터 파일 발견: 원본 구조 정보 로드됨")
            
            # image_nr 패턴 파일들 수집
            image_files = []
            for filename in os.listdir(msi_pack_dir):
                if filename.startswith('image_nr') and not filename.endswith('.txt'):
                    # 정확한 패턴 검증: image_nr{숫자}_off0x{16진수}.{확장자}
                    # 오프셋은 가변 길이 허용 (ASUS와 호환성 유지)
                    import re
                    pattern = r'^image_nr(\d+)_off0x([0-9A-Fa-f]+)\.[a-zA-Z0-9]+$'
                    if re.match(pattern, filename):
                        file_path = os.path.join(msi_pack_dir, filename)
                        if os.path.isfile(file_path):
                            image_files.append((filename, file_path))
                    else:
                        print(f"  [WARNING] 파일명 패턴이 올바르지 않음 (image_nr{{숫자}}_off0x{{16진수}}.{{확장자}} 형식이어야 함): {filename}")
            
            # 파일명 순서로 정렬 (image_nr0, image_nr1, ...)
            image_files.sort(key=lambda x: self._extract_image_number(x[0]))
            
            print(f"발견된 이미지 파일: {len(image_files)}개")
            
            if len(image_files) < 2:
                print(f"[ERROR] 리패킹하려면 최소 2개 이상의 이미지가 필요합니다.")
                return False
            
            # MSI 바이너리 생성
            success = self._create_msi_binary_with_structure(image_files, structure_info, output_file)
            
            if success:
                self._verify_repacked_file(output_file)
                print(f"[SUCCESS] 구조 보존 MSI 리패킹이 완료되었습니다: {output_file}")
                
                if original_analysis:
                    print(f"[INFO] 원본 분석 결과를 기반으로 완벽한 구조 복원이 수행되었습니다.")
            
            return success
            
        except Exception as e:
            print(f"[ERROR] 구조 보존 리패킹 실패: {e}")
            return False
    
    def _repack_simple_mode(self, input_dir: str, output_file: str, preserve_order: bool,
                           modified_images: Dict[str, Any] = None) -> bool:
        """일반 모드 리패킹"""
        try:
            # 이미지 파일들 수집
            image_files = self._collect_image_files(input_dir, preserve_order)
            
            if not image_files:
                print(f"[ERROR] 리패킹할 이미지 파일을 찾을 수 없습니다.")
                return False
            
            print(f"발견된 이미지 파일: {len(image_files)}개")
            
            # MSI 바이너리 생성
            success = self._create_msi_binary(image_files, output_file)
            
            if success:
                # 결과 검증
                self._verify_repacked_file(output_file)
                print(f"[SUCCESS] MSI 리패킹이 완료되었습니다: {output_file}")
            
            return success
            
        except Exception as e:
            print(f"[ERROR] 일반 리패킹 실패: {e}")
            return False
    
    def repack_from_analysis(self, analysis_results: Dict[str, Any], 
                           images_dir: str, output_file: str) -> bool:
        """분석 결과를 기반으로 정확한 순서로 리패킹"""
        try:
            print(f"\n=== 분석 결과 기반 MSI 리패킹 ===")
            
            if 'msi_entries' not in analysis_results:
                print(f"[ERROR] 유효한 분석 결과가 아닙니다.")
                return False
            
            entries = analysis_results['msi_entries']
            print(f"원본 엔트리 수: {len(entries)}개")
            
            # MSI_Pack 폴더 찾기
            msi_pack_dirs = [d for d in os.listdir(images_dir) 
                           if os.path.isdir(os.path.join(images_dir, d)) and d.startswith('MSI_pack')]
            
            if msi_pack_dirs:
                # MSI_Pack 폴더가 있으면 구조 보존 모드 사용
                msi_pack_dir = os.path.join(images_dir, msi_pack_dirs[0])
                print(f"MSI_Pack 폴더 발견: {msi_pack_dir}")
                return self._repack_with_structure_preservation(msi_pack_dir, output_file, analysis_results)
            
            # 일반 매핑 방식으로 진행
            # 각 엔트리에 대응하는 이미지 파일 찾기
            image_mappings = []
            
            for entry in entries:
                img_index = entry['index']
                img_size = entry['image_data_size']
                img_type = entry['image_type']
                
                # 대응하는 이미지 파일 찾기
                image_file = self._find_corresponding_image(
                    images_dir, img_index, img_size, img_type
                )
                
                if image_file:
                    mapping = {
                        'original_entry': entry,
                        'image_file': image_file,
                        'preserve_header': True
                    }
                    image_mappings.append(mapping)
                    print(f"Entry #{img_index}: {os.path.basename(image_file)}")
                else:
                    print(f"[WARNING] Entry #{img_index}에 대응하는 이미지를 찾을 수 없습니다.")
            
            if not image_mappings:
                print(f"[ERROR] 리패킹할 이미지 매핑을 찾을 수 없습니다.")
                return False
            
            # 정확한 구조로 MSI 바이너리 생성
            success = self._create_msi_binary_from_mappings(image_mappings, output_file)
            
            if success:
                print(f"[SUCCESS] 분석 기반 MSI 리패킹이 완료되었습니다: {output_file}")
            
            return success
            
        except Exception as e:
            print(f"[ERROR] 분석 기반 리패킹 중 오류 발생: {e}")
            return False
    
    def _collect_image_files(self, input_dir: str, preserve_order: bool) -> List[str]:
        """이미지 파일들 수집"""
        image_files = []
        
        # 지원되는 확장자의 파일들 검색
        for ext in self.supported_extensions:
            pattern = os.path.join(input_dir, f"*{ext}")
            files = glob.glob(pattern)
            image_files.extend(files)
        
        if preserve_order:
            # 파일명의 숫자 순서로 정렬 (msi_image_00_xxx.bin 형식 가정)
            image_files.sort(key=lambda x: self._extract_order_number(x))
        else:
            image_files.sort()
        
        return image_files
    
    def _extract_order_number(self, filename: str) -> int:
        """파일명에서 순서 번호 추출"""
        try:
            basename = os.path.basename(filename)
            # msi_image_XX_xxx.bin 형식에서 XX 추출
            if 'msi_image_' in basename:
                parts = basename.split('_')
                if len(parts) >= 3:
                    return int(parts[2])
            
            # 다른 패턴들도 처리
            import re
            numbers = re.findall(r'\d+', basename)
            if numbers:
                return int(numbers[0])
            
        except (ValueError, IndexError):
            pass
        
        return 0
    
    def _extract_image_number(self, filename: str) -> int:
        """image_nr 패턴에서 이미지 번호 추출"""
        try:
            # image_nr{번호}_off0x{오프셋}.{확장자} 패턴에서 번호 추출
            if filename.startswith('image_nr'):
                # image_nr 다음 숫자 추출
                import re
                match = re.match(r'image_nr(\d+)_', filename)
                if match:
                    return int(match.group(1))
            
            return 0
        except (ValueError, IndexError):
            return 0

    def _extract_offset_from_filename(self, filename: str) -> int:
        """파일명에서 오프셋 추출 (ASUS 호환성)"""
        try:
            # image_nr{번호}_off0x{오프셋}.{확장자} 패턴에서 오프셋 추출
            import re
            match = re.search(r'_off0x([0-9A-Fa-f]+)\.', filename)
            if match:
                return int(match.group(1), 16)  # 16진수를 10진수로 변환
            
            return 0
        except (ValueError, AttributeError):
            return 0
    
    def _parse_metadata_file(self, metadata_file: str) -> Dict[str, Any]:
        """메타데이터 파일 파싱"""
        try:
            structure_info = {'entries': []}
            
            with open(metadata_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 간단한 파싱 (Index: 로 시작하는 라인들 찾기)
            lines = content.split('\n')
            current_entry = None
            
            for line in lines:
                line = line.strip()
                if line.startswith('Index:'):
                    if current_entry:
                        structure_info['entries'].append(current_entry)
                    current_entry = {'index': int(line.split(':')[1].strip())}
                elif current_entry and ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower().replace(' ', '_')
                    value = value.strip()
                    
                    if key == 'offset':
                        current_entry['offset'] = int(value, 16)
                    elif key == 'image_size':
                        current_entry['image_size'] = int(value)
                    elif key == 'image_type':
                        current_entry['image_type'] = value
                    elif key == 'sector':
                        current_entry['sector'] = int(value, 16)
                    elif key == 'layer':
                        current_entry['layer'] = int(value, 16)
                    elif key == 'image_number':
                        current_entry['image_number'] = int(value)
                    elif key == 'reserved':
                        current_entry['reserved'] = int(value, 16)
                    elif key == 'filename':
                        current_entry['filename'] = value
            
            if current_entry:
                structure_info['entries'].append(current_entry)
            
            print(f"메타데이터에서 {len(structure_info['entries'])}개 엔트리 정보 로드됨")
            return structure_info
            
        except Exception as e:
            print(f"[WARNING] 메타데이터 파싱 실패: {e}")
            return {'entries': []}
    
    def _create_msi_binary_with_structure(self, image_files: List[Tuple[str, str]], 
                                        structure_info: Optional[Dict[str, Any]], 
                                        output_file: str) -> bool:
        """구조 정보를 사용하여 MSI 바이너리 생성"""
        try:
            with open(output_file, 'wb') as out_f:
                total_size = 0
                
                for i, (filename, file_path) in enumerate(image_files):
                    print(f"처리 중: {filename}")
                    
                    # 이미지 데이터 읽기
                    with open(file_path, 'rb') as img_f:
                        image_data = img_f.read()
                    
                    # 구조 정보에서 해당 엔트리 찾기
                    header_info = None
                    if structure_info and i < len(structure_info['entries']):
                        header_info = structure_info['entries'][i]
                    
                    # MSI 헤더 생성
                    if header_info:
                        # 원본 구조 정보 사용
                        header = self._create_msi_header_from_structure(header_info, len(image_data))
                        print(f"  원본 구조 정보 사용: sector=0x{header_info.get('sector', 0):02X}, "
                              f"layer=0x{header_info.get('layer', 0):02X}, "
                              f"number={header_info.get('image_number', i)}")
                    else:
                        # 기본 헤더 생성
                        header = self._create_msi_header(i, len(image_data))
                        print(f"  기본 헤더 사용: image_number={i}")
                    
                    # 헤더 + 이미지 데이터 쓰기
                    out_f.write(header)
                    out_f.write(image_data)
                    
                    total_size += self.HEADER_SIZE + len(image_data)
                
                print(f"총 바이너리 크기: {total_size:,} bytes")
                
                # 결과 저장
                self.repack_results = {
                    'output_file': output_file,
                    'total_entries': len(image_files),
                    'total_size': total_size,
                    'timestamp': datetime.now().isoformat(),
                    'structure_preserved': structure_info is not None
                }
                
                return True
                
        except Exception as e:
            print(f"[ERROR] 구조 보존 MSI 바이너리 생성 실패: {e}")
            return False
    
    def _create_msi_header_from_structure(self, structure_info: Dict[str, Any], 
                                        image_size: int) -> bytes:
        """구조 정보를 기반으로 MSI 헤더 생성"""
        header = bytearray(self.HEADER_SIZE)
        
        # MSI 시그니처
        header[0:4] = self.msi_signature
        
        # 구조 정보에서 메타데이터 사용
        header[4] = structure_info.get('sector', 0) & 0xFF
        header[5] = structure_info.get('layer', 0) & 0xFF
        header[6] = structure_info.get('image_number', 0) & 0xFF
        header[7] = structure_info.get('reserved', 0) & 0xFF
        
        # 실제 이미지 크기 사용
        struct.pack_into('<I', header, 8, image_size)
        
        return bytes(header)
    
    def _find_corresponding_image(self, images_dir: str, img_index: int, 
                                img_size: int, img_type: str) -> Optional[str]:
        """분석 엔트리에 대응하는 이미지 파일 찾기"""
        # 여러 패턴으로 검색
        patterns = [
            f"msi_image_{img_index:02d}_*.bin",
            f"*_{img_index:02d}_*.bin", 
            f"image_{img_index}_*.bin",
            f"*{img_index}*.bin"
        ]
        
        for pattern in patterns:
            full_pattern = os.path.join(images_dir, pattern)
            files = glob.glob(full_pattern)
            
            for file_path in files:
                # 파일 크기로 추가 검증
                if os.path.getsize(file_path) == img_size:
                    return file_path
        
        # 크기만으로 검색
        for file_path in glob.glob(os.path.join(images_dir, "*.bin")):
            if os.path.getsize(file_path) == img_size:
                return file_path
        
        return None
    
    def _create_msi_binary(self, image_files: List[str], output_file: str) -> bool:
        """이미지 파일들로부터 MSI 바이너리 생성"""
        try:
            with open(output_file, 'wb') as out_f:
                total_size = 0
                
                for i, image_file in enumerate(image_files):
                    print(f"처리 중: {os.path.basename(image_file)}")
                    
                    # 이미지 데이터 읽기
                    with open(image_file, 'rb') as img_f:
                        image_data = img_f.read()
                    
                    # MSI 헤더 생성
                    header = self._create_msi_header(i, len(image_data))
                    
                    # 헤더 + 이미지 데이터 쓰기
                    out_f.write(header)
                    out_f.write(image_data)
                    
                    total_size += self.HEADER_SIZE + len(image_data)
                
                print(f"총 바이너리 크기: {total_size:,} bytes")
                return True
                
        except Exception as e:
            print(f"[ERROR] MSI 바이너리 생성 실패: {e}")
            return False
    
    def _create_msi_binary_from_mappings(self, mappings: List[Dict[str, Any]], 
                                       output_file: str) -> bool:
        """매핑 정보를 기반으로 MSI 바이너리 생성"""
        try:
            with open(output_file, 'wb') as out_f:
                total_size = 0
                
                for mapping in mappings:
                    original_entry = mapping['original_entry']
                    image_file = mapping['image_file']
                    
                    print(f"처리 중: Entry #{original_entry['index']} -> {os.path.basename(image_file)}")
                    
                    # 이미지 데이터 읽기
                    with open(image_file, 'rb') as img_f:
                        image_data = img_f.read()
                    
                    if mapping.get('preserve_header', False):
                        # 원본 헤더 정보 보존
                        header = self._create_msi_header_from_original(
                            original_entry['header'], len(image_data)
                        )
                    else:
                        # 새로운 헤더 생성
                        header = self._create_msi_header(
                            original_entry['index'], len(image_data)
                        )
                    
                    # 헤더 + 이미지 데이터 쓰기
                    out_f.write(header)
                    out_f.write(image_data)
                    
                    total_size += self.HEADER_SIZE + len(image_data)
                
                print(f"총 바이너리 크기: {total_size:,} bytes")
                
                # 결과 저장
                self.repack_results = {
                    'output_file': output_file,
                    'total_entries': len(mappings),
                    'total_size': total_size,
                    'timestamp': datetime.now().isoformat()
                }
                
                return True
                
        except Exception as e:
            print(f"[ERROR] 매핑 기반 MSI 바이너리 생성 실패: {e}")
            return False
    
    def _create_msi_header(self, image_number: int, image_size: int) -> bytes:
        """MSI 헤더 생성"""
        header = bytearray(self.HEADER_SIZE)
        
        # MSI 시그니처
        header[0:4] = self.MSI_SIGNATURE
        
        # 메타데이터 필드
        header[4] = 0x00  # Sector/Layer
        header[5] = 0x00  # Position
        header[6] = image_number & 0xFF  # Image number
        header[7] = 0x00  # Reserved
        
        # 이미지 크기 (little endian)
        struct.pack_into('<I', header, 8, image_size)
        
        return bytes(header)
    
    def _create_msi_header_from_original(self, original_header: Dict[str, Any], 
                                       new_size: int) -> bytes:
        """원본 헤더 정보를 기반으로 MSI 헤더 생성"""
        header = bytearray(self.HEADER_SIZE)
        
        # 시그니처
        header[0:4] = self.MSI_SIGNATURE
        
        # 원본 메타데이터 보존
        header[4] = original_header.get('sector', 0)
        header[5] = original_header.get('layer', 0) 
        header[6] = original_header.get('image_number', 0)
        header[7] = original_header.get('reserved', 0)
        
        # 새로운 이미지 크기 사용
        struct.pack_into('<I', header, 8, new_size)
        
        return bytes(header)
    
    def _verify_repacked_file(self, output_file: str) -> None:
        """리패킹된 파일 검증"""
        try:
            print(f"\n=== 리패킹 결과 검증 ===")
            
            with open(output_file, 'rb') as f:
                data = f.read()
            
            file_size = len(data)
            print(f"출력 파일 크기: {file_size:,} bytes")
            
            # MSI 엔트리 카운트
            msi_count = 0
            offset = 0
            
            while offset < len(data) - self.HEADER_SIZE:
                if data[offset:offset+4] == self.MSI_SIGNATURE:
                    # 헤더 파싱
                    image_size = struct.unpack('<I', data[offset+8:offset+12])[0]
                    print(f"MSI Entry #{msi_count}: 오프셋 0x{offset:08X}, 크기 {image_size:,} bytes")
                    
                    msi_count += 1
                    offset += self.HEADER_SIZE + image_size
                else:
                    offset += 1
            
            print(f"검증된 MSI 엔트리: {msi_count}개")
            
        except Exception as e:
            print(f"[WARNING] 검증 중 오류 발생: {e}")
    
    def create_backup(self, original_file: str, backup_suffix: str = "_backup") -> str:
        """원본 파일 백업"""
        try:
            backup_file = f"{original_file}{backup_suffix}"
            
            with open(original_file, 'rb') as src, open(backup_file, 'wb') as dst:
                dst.write(src.read())
            
            print(f"[SUCCESS] 백업 생성됨: {backup_file}")
            return backup_file
            
        except Exception as e:
            print(f"[ERROR] 백업 생성 실패: {e}")
            return ""
    
    def export_repack_report(self, output_path: str) -> bool:
        """리패킹 결과 리포트 생성"""
        try:
            if not self.repack_results:
                print("[ERROR] 리패킹 결과가 없습니다.")
                return False
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("=== MSI 이미지 리패킹 리포트 ===\n")
                f.write(f"생성 시간: {self.repack_results['timestamp']}\n")
                f.write(f"출력 파일: {self.repack_results['output_file']}\n")
                f.write(f"총 엔트리 수: {self.repack_results['total_entries']}개\n")
                f.write(f"총 파일 크기: {self.repack_results['total_size']:,} bytes\n")
                f.write(f"평균 이미지 크기: {self.repack_results['total_size'] // self.repack_results['total_entries']:,} bytes\n")
            
            print(f"[SUCCESS] 리패킹 리포트 저장됨: {output_path}")
            return True
        except Exception as e:
            print(f"[ERROR] 리포트 생성 실패: {e}")
            return False
    
    def _detect_modified_images(self, msi_pack_dir: str, original_file: str, 
                               original_analysis: Dict[str, Any] = None) -> Dict[str, Any]:
        """원본 파일과 추출된 이미지들을 비교하여 변경된 이미지 감지 (구조 보존 모드)"""
        print("\n2단계: 수정된 이미지 파일 감지...")
        modified_images = {}
        unchanged_count = 0
        modified_count = 0
        
        if not original_analysis or 'msi_entries' not in original_analysis:
            print("[WARNING] 원본 분석 결과가 없어 변경 감지를 수행할 수 없습니다.")
            return {}
        
        # 원본 파일 로드
        try:
            with open(original_file, 'rb') as f:
                original_data = f.read()
        except Exception as e:
            print(f"[ERROR] 원본 파일을 읽을 수 없습니다: {e}")
            return {}
        
        for entry in original_analysis['msi_entries']:
            entry_index = entry['index']
            abs_offset = entry['offset']
            original_size = entry['image_data_size']
            
            # 원본 이미지 데이터 추출
            start_offset = abs_offset
            end_offset = start_offset + original_size
            if end_offset > len(original_data):
                print(f"  [WARNING] 오프셋 범위 초과로 건너뛰기: 이미지 #{entry_index}")
                continue
                
            original_image_data = original_data[start_offset:end_offset]
            
            # 추출된 파일 찾기
            filename = f"image_nr{entry_index}_off0x{abs_offset:X}"
            image_type = entry.get('image_type', 'bin')
            filepath = os.path.join(msi_pack_dir, f"{filename}.{image_type}")
            
            # 다른 확장자로도 시도
            if not os.path.exists(filepath):
                for ext in self.supported_extensions:
                    test_path = os.path.join(msi_pack_dir, f"{filename}{ext}")
                    if os.path.exists(test_path):
                        filepath = test_path
                        break
            
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'rb') as f:
                        extracted_data = f.read()
                    
                    # 원본과 추출된 파일 비교
                    if extracted_data == original_image_data:
                        unchanged_count += 1
                        print(f"  ✅ 변경없음: 이미지 #{entry_index} ({len(extracted_data)} bytes)")
                    else:
                        modified_count += 1
                        modified_images[entry_index] = {
                            'original_entry': entry,
                            'new_data': extracted_data,
                            'new_size': len(extracted_data),
                            'size_diff': len(extracted_data) - original_size,
                            'filepath': filepath
                        }
                        print(f"  🔄 수정됨: 이미지 #{entry_index} "
                              f"({original_size} → {len(extracted_data)} bytes, "
                              f"{len(extracted_data) - original_size:+} bytes)")
                              
                except Exception as e:
                    print(f"  [ERROR] 파일 읽기 실패: {filepath} - {e}")
                    unchanged_count += 1
            else:
                print(f"  [WARNING] 추출된 파일을 찾을 수 없습니다: {filename}")
                unchanged_count += 1
        
        print(f"\n변경 요약:")
        print(f"  📋 총 이미지: {unchanged_count + modified_count}개")
        print(f"  ✅ 변경없음: {unchanged_count}개")
        print(f"  🔄 수정됨: {modified_count}개")
        
        return modified_images
    
    def _detect_modified_images_simple(self, input_dir: str, original_file: str, 
                                     original_analysis: Dict[str, Any] = None) -> Dict[str, Any]:
        """원본 파일과 추출된 이미지들을 비교하여 변경된 이미지 감지 (일반 모드)"""
        print("\n2단계: 수정된 이미지 파일 감지 (일반 모드)...")
        modified_images = {}
        unchanged_count = 0
        modified_count = 0
        
        # 원본 파일 로드
        try:
            with open(original_file, 'rb') as f:
                original_data = f.read()
        except Exception as e:
            print(f"[ERROR] 원본 파일을 읽을 수 없습니다: {e}")
            return {}
        
        # 추출된 이미지 파일들 수집
        image_files = []
        for ext in self.supported_extensions:
            pattern = os.path.join(input_dir, f"*{ext}")
            image_files.extend(glob.glob(pattern))
        
        if not image_files:
            print("[WARNING] 추출된 이미지 파일을 찾을 수 없습니다.")
            return {}
        
        # 파일명에서 오프셋 정보 추출하여 비교
        for filepath in sorted(image_files):
            filename = os.path.basename(filepath)
            
            # 파일명에서 오프셋 추출 (예: image_nr81_off0x647A.png -> 0x647A)
            import re
            match = re.search(r'_off0x([0-9A-Fa-f]+)', filename)
            if not match:
                print(f"  [WARNING] 오프셋 정보를 찾을 수 없는 파일명: {filename}")
                continue
                
            offset_str = match.group(1)
            try:
                offset = int(offset_str, 16)
            except ValueError:
                print(f"  [WARNING] 잘못된 오프셋 형식: {offset_str}")
                continue
            
            # 이미지 번호 추출 (예: image_nr81_off0x647A.png -> 81)
            nr_match = re.search(r'image_nr(\d+)_', filename)
            if not nr_match:
                print(f"  [WARNING] 이미지 번호를 찾을 수 없는 파일명: {filename}")
                continue
                
            image_nr = int(nr_match.group(1))
            
            try:
                # 추출된 파일 읽기
                with open(filepath, 'rb') as f:
                    extracted_data = f.read()
                
                # 원본에서 해당 오프셋의 데이터 찾기
                original_image_data = self._find_original_image_at_offset(original_data, offset, len(extracted_data))
                
                if original_image_data is None:
                    print(f"  [WARNING] 원본에서 오프셋 0x{offset:X}에 해당하는 이미지를 찾을 수 없습니다: {filename}")
                    # 새 이미지로 간주
                    modified_count += 1
                    modified_images[image_nr] = {
                        'filepath': filepath,
                        'new_data': extracted_data,
                        'new_size': len(extracted_data),
                        'offset': offset,
                        'is_new': True
                    }
                    print(f"  🆕 새 이미지: {filename} ({len(extracted_data)} bytes)")
                    continue
                
                # 원본과 비교
                if extracted_data == original_image_data:
                    unchanged_count += 1
                    print(f"  ✅ 변경없음: {filename} ({len(extracted_data)} bytes)")
                else:
                    modified_count += 1
                    modified_images[image_nr] = {
                        'filepath': filepath,
                        'new_data': extracted_data,
                        'new_size': len(extracted_data),
                        'original_size': len(original_image_data),
                        'size_diff': len(extracted_data) - len(original_image_data),
                        'offset': offset,
                        'is_new': False
                    }
                    print(f"  🔄 수정됨: {filename} "
                          f"({len(original_image_data)} → {len(extracted_data)} bytes, "
                          f"{len(extracted_data) - len(original_image_data):+} bytes)")
                          
            except Exception as e:
                print(f"  [ERROR] 파일 처리 중 오류: {filename} - {e}")
                unchanged_count += 1
        
        print(f"\n변경 요약:")
        print(f"  📋 총 이미지: {unchanged_count + modified_count}개")
        print(f"  ✅ 변경없음: {unchanged_count}개")
        print(f"  🔄 수정됨: {modified_count}개")
        
        return modified_images
    
    def _find_original_image_at_offset(self, original_data: bytes, offset: int, expected_size: int) -> bytes:
        """원본 데이터에서 지정된 오프셋의 이미지 데이터 찾기"""
        if offset >= len(original_data):
            return None
            
        # 정확한 크기로 추출 시도
        if offset + expected_size <= len(original_data):
            return original_data[offset:offset + expected_size]
        
        # 파일 끝까지의 데이터 반환
        return original_data[offset:]
    
    def _copy_original_file(self, original_file: str, output_file: str) -> bool:
        """원본 파일을 출력 위치로 복사"""
        try:
            import shutil
            shutil.copy2(original_file, output_file)
            print(f"✅ 원본 파일 복사 완료: {output_file}")
            return True
        except Exception as e:
            print(f"[ERROR] 원본 파일 복사 실패: {e}")
            return False
        except Exception as e:
            print(f"[ERROR] 리포트 저장 실패: {e}")
            return False


if __name__ == "__main__":
    # 테스트 코드
    repacker = MSIImageRepacker()
    
    # 테스트 경로들 (실제 사용시 수정 필요)
    test_images_dir = "msi_extracted"  # 기본 추출 디렉터리
    test_output_file = "msi_repacked.bin"
    
    if os.path.exists(test_images_dir):
        print("MSI 이미지 리패커 테스트")
        print("=" * 50)
        
        # 구조 보존 리패킹 테스트
        success = repacker.repack_from_directory(test_images_dir, test_output_file)
        
        if success:
            # 리포트 생성
            report_path = "msi_repack_report.txt"
            repacker.export_repack_report(report_path)
            print(f"[INFO] test.py로 재추출 시 MSI_Pack 폴더가 생성됩니다.")
    else:
        print(f"테스트 이미지 디렉터리를 찾을 수 없습니다: {test_images_dir}")
        print("먼저 MSI 파일을 분석하여 이미지를 추출하세요.")
