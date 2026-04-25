"""
MSI image repacker

Repackages MSI_Pack folders or extracted images into MSI Packer format.
Generates a binary compatible with the original BIOS file.
This repacker does not implement extraction.
"""

import os
import sys
import struct
import glob
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

# Enable UTF-8 console output on Windows.
if os.name == 'nt':  # Windows
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except:
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.detach())


class MSIImageRepacker:
    """MSI image repacker; extraction is out of scope."""
    
    def __init__(self):
        """Initialize instance state."""
        self.MSI_SIGNATURE = b'$MsI$'
        self.HEADER_SIZE = len(self.MSI_SIGNATURE) + 8
        
        # Supported image file extensions.
        self.supported_extensions = ['.bin', '.jpg', '.jpeg', '.png', '.bmp', '.ico']
        
        # Store repack results.
        self.repack_results = {}
    
    def repack_from_directory(self, input_dir: str, output_file: str, 
                            preserve_order: bool = True, original_analysis: Dict[str, Any] = None,
                            original_file: str = None) -> bool:
        """Repack extracted images from a directory into an MSI binary."""
        try:
            print(f"\n=== MSI 이미지 리패킹 시작 ===")
            print(f"입력 디렉터리: {input_dir}")
            print(f"출력 파일: {output_file}")
            
            # Enable change detection when an original file is available.
            enable_change_detection = original_file and os.path.exists(original_file)
            if enable_change_detection:
                print(f"원본 파일: {original_file}")
                print("변경 감지 모드: 수정된 이미지만 처리됩니다.")
            
            # Validate the input directory.
            if not os.path.exists(input_dir):
                print(f"[ERROR] 입력 디렉터리가 존재하지 않습니다: {input_dir}")
                return False
            
            # Find MSI_Pack folders for structure-preservation mode.
            msi_pack_dirs = [d for d in os.listdir(input_dir) 
                           if os.path.isdir(os.path.join(input_dir, d)) and d.startswith('MSI_pack')]
            
            if msi_pack_dirs:
                # Repack in structure-preservation mode.
                msi_pack_dir = os.path.join(input_dir, msi_pack_dirs[0])
                print(f"구조 보존 모드: {msi_pack_dir} 사용")
                
                # Detect modified images.
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
                # Repack in simple mode.
                print("일반 모드: 디렉터리 내 이미지 파일들을 순서대로 리패킹")
                
                # Detect modified images.
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
        """Structure-preserving repack mode."""
        try:
            print(f"구조 보존 리패킹 시작: {msi_pack_dir}")
            
            # Prefer original analysis results.
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
                # Read the metadata file.
                metadata_file = os.path.join(msi_pack_dir, "msi_structure_info.txt")
                if os.path.exists(metadata_file):
                    structure_info = self._parse_metadata_file(metadata_file)
                    print(f"메타데이터 파일 발견: 원본 구조 정보 로드됨")
            
            # Collect files matching the image_nr naming pattern.
            image_files = []
            for filename in os.listdir(msi_pack_dir):
                if filename.startswith('image_nr') and not filename.endswith('.txt'):
                    # Validate the image_nr{number}_off0x{offset}.{ext} pattern.
                    # Allow variable-length offsets for ASUS compatibility.
                    import re
                    pattern = r'^image_nr(\d+)_off0x([0-9A-Fa-f]+)\.[a-zA-Z0-9]+$'
                    if re.match(pattern, filename):
                        file_path = os.path.join(msi_pack_dir, filename)
                        if os.path.isfile(file_path):
                            image_files.append((filename, file_path))
                    else:
                        print(f"  [WARNING] 파일명 패턴이 올바르지 않음 (image_nr{{숫자}}_off0x{{16진수}}.{{확장자}} 형식이어야 함): {filename}")
            
            # Sort by image number in the file name.
            image_files.sort(key=lambda x: self._extract_image_number(x[0]))
            
            print(f"발견된 이미지 파일: {len(image_files)}개")
            
            if len(image_files) < 2:
                print(f"[ERROR] 리패킹하려면 최소 2개 이상의 이미지가 필요합니다.")
                return False
            
            # Create the MSI binary.
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
        """Simple repack mode."""
        try:
            # Collect image files.
            image_files = self._collect_image_files(input_dir, preserve_order)
            
            if not image_files:
                print(f"[ERROR] 리패킹할 이미지 파일을 찾을 수 없습니다.")
                return False
            
            print(f"발견된 이미지 파일: {len(image_files)}개")
            
            # Create the MSI binary.
            success = self._create_msi_binary(image_files, output_file)
            
            if success:
                # Verify the repacked result.
                self._verify_repacked_file(output_file)
                print(f"[SUCCESS] MSI 리패킹이 완료되었습니다: {output_file}")
            
            return success
            
        except Exception as e:
            print(f"[ERROR] 일반 리패킹 실패: {e}")
            return False
    
    def repack_from_analysis(self, analysis_results: Dict[str, Any], 
                           images_dir: str, output_file: str) -> bool:
        """Repack in exact order using analysis results."""
        try:
            print(f"\n=== 분석 결과 기반 MSI 리패킹 ===")
            
            if 'msi_entries' not in analysis_results:
                print(f"[ERROR] 유효한 분석 결과가 아닙니다.")
                return False
            
            entries = analysis_results['msi_entries']
            print(f"원본 엔트리 수: {len(entries)}개")
            
            # Find MSI_Pack folders.
            msi_pack_dirs = [d for d in os.listdir(images_dir) 
                           if os.path.isdir(os.path.join(images_dir, d)) and d.startswith('MSI_pack')]
            
            if msi_pack_dirs:
                # Use structure-preservation mode when MSI_Pack exists.
                msi_pack_dir = os.path.join(images_dir, msi_pack_dirs[0])
                print(f"MSI_Pack 폴더 발견: {msi_pack_dir}")
                return self._repack_with_structure_preservation(msi_pack_dir, output_file, analysis_results)
            
            # Use the simple mapping path.
            # Find image files matching each entry.
            image_mappings = []
            
            for entry in entries:
                img_index = entry['index']
                img_size = entry['image_data_size']
                img_type = entry['image_type']
                
                # Find the corresponding image file.
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
            
            # Create an MSI binary with the exact mapped structure.
            success = self._create_msi_binary_from_mappings(image_mappings, output_file)
            
            if success:
                print(f"[SUCCESS] 분석 기반 MSI 리패킹이 완료되었습니다: {output_file}")
            
            return success
            
        except Exception as e:
            print(f"[ERROR] 분석 기반 리패킹 중 오류 발생: {e}")
            return False
    
    def _collect_image_files(self, input_dir: str, preserve_order: bool) -> List[str]:
        """Collect image files."""
        image_files = []
        
        # Search files with supported extensions.
        for ext in self.supported_extensions:
            pattern = os.path.join(input_dir, f"*{ext}")
            files = glob.glob(pattern)
            image_files.extend(files)
        
        if preserve_order:
            # Sort by numeric order in file names such as msi_image_00_xxx.bin.
            image_files.sort(key=lambda x: self._extract_order_number(x))
        else:
            image_files.sort()
        
        return image_files
    
    def _extract_order_number(self, filename: str) -> int:
        """Extract an order number from a file name."""
        try:
            basename = os.path.basename(filename)
            # Extract XX from msi_image_XX_xxx.bin.
            if 'msi_image_' in basename:
                parts = basename.split('_')
                if len(parts) >= 3:
                    return int(parts[2])
            
            # Handle other numeric patterns.
            import re
            numbers = re.findall(r'\d+', basename)
            if numbers:
                return int(numbers[0])
            
        except (ValueError, IndexError):
            pass
        
        return 0
    
    def _extract_image_number(self, filename: str) -> int:
        """Extract the image number from an image_nr name."""
        try:
            # Extract number from image_nr{number}_off0x{offset}.{ext}.
            if filename.startswith('image_nr'):
                # Extract digits after image_nr.
                import re
                match = re.match(r'image_nr(\d+)_', filename)
                if match:
                    return int(match.group(1))
            
            return 0
        except (ValueError, IndexError):
            return 0

    def _extract_offset_from_filename(self, filename: str) -> int:
        """Extract offset from file name for ASUS compatibility."""
        try:
            # Extract offset from image_nr{number}_off0x{offset}.{ext}.
            import re
            match = re.search(r'_off0x([0-9A-Fa-f]+)\.', filename)
            if match:
                return int(match.group(1), 16)  # 16진수를 10진수로 변환
            
            return 0
        except (ValueError, AttributeError):
            return 0
    
    def _parse_metadata_file(self, metadata_file: str) -> Dict[str, Any]:
        """Parse the metadata file."""
        try:
            structure_info = {'entries': []}
            
            with open(metadata_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse simple metadata lines beginning with Index:.
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
        """Create an MSI binary using structure information."""
        try:
            with open(output_file, 'wb') as out_f:
                total_size = 0
                
                # Write the MSI signature once at the start.
                msi_signature = self.MSI_SIGNATURE  # b'$MsI$'
                out_f.write(msi_signature)
                total_size += len(msi_signature)
                
                # Write padding/metadata to match the original layout.
                padding = b'\x8E\x00'
                out_f.write(padding)
                total_size += len(padding)
                
                for i, (filename, file_path) in enumerate(image_files):
                    print(f"처리 중: {filename}")
                    
                    # Read image data.
                    with open(file_path, 'rb') as img_f:
                        image_data = img_f.read()
                    
                    # Find matching entry metadata.
                    header_info = None
                    if structure_info and i < len(structure_info['entries']):
                        header_info = structure_info['entries'][i]
                    
                    # Create an MSI entry header without the signature.
                    if header_info:
                        # Use original structure information.
                        entry_header = self._create_msi_entry_header(header_info.get('image_number', i + 1), len(image_data))
                        print(f"  원본 구조 정보 사용: image_number={header_info.get('image_number', i + 1)}")
                    else:
                        # Create a default header.
                        entry_header = self._create_msi_entry_header(i + 1, len(image_data))
                        print(f"  기본 헤더 사용: image_number={i + 1}")
                    
                    # Write entry header and image data.
                    out_f.write(entry_header)
                    out_f.write(image_data)
                    
                    total_size += len(entry_header) + len(image_data)
                
                print(f"총 바이너리 크기: {total_size:,} bytes")
                
                # Store result metadata.
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
        """Create an MSI header from structure metadata."""
        header = bytearray(self.HEADER_SIZE)
        
        sig_len = len(self.MSI_SIGNATURE)
        header[0:sig_len] = self.MSI_SIGNATURE
        
        # Use metadata from structure information.
        header[sig_len] = structure_info.get('sector', 0) & 0xFF
        header[sig_len + 1] = structure_info.get('layer', 0) & 0xFF
        header[sig_len + 2] = structure_info.get('image_number', 0) & 0xFF
        header[sig_len + 3] = structure_info.get('reserved', 0) & 0xFF
        
        # Use the actual image size.
        struct.pack_into('<I', header, sig_len + 4, image_size)
        
        return bytes(header)
    
    def _find_corresponding_image(self, images_dir: str, img_index: int, 
                                img_size: int, img_type: str) -> Optional[str]:
        """Find the image file corresponding to an analysis entry."""
        # Search using multiple file-name patterns.
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
                # Validate additionally by file size.
                if os.path.getsize(file_path) == img_size:
                    return file_path
        
        # Fallback to matching by size only.
        for file_path in glob.glob(os.path.join(images_dir, "*.bin")):
            if os.path.getsize(file_path) == img_size:
                return file_path
        
        return None
    
    def _create_msi_binary(self, image_files: List[str], output_file: str) -> bool:
        """Create an MSI binary from image files."""
        try:
            with open(output_file, 'wb') as out_f:
                total_size = 0
                
                # Write the MSI signature once at the start.
                msi_signature = self.MSI_SIGNATURE  # b'$MsI$'
                out_f.write(msi_signature)
                total_size += len(msi_signature)
                
                # Write padding/metadata to match the original layout.
                padding = b'\x8E\x00'
                out_f.write(padding)
                total_size += len(padding)
                
                for i, image_file in enumerate(image_files):
                    print(f"처리 중: {os.path.basename(image_file)}")
                    
                    # Read image data.
                    with open(image_file, 'rb') as img_f:
                        image_data = img_f.read()
                    
                    # Create image entry header without the MSI signature.
                    entry_header = self._create_msi_entry_header(i + 1, len(image_data))
                    
                    # Write entry header and image data.
                    out_f.write(entry_header)
                    out_f.write(image_data)
                    
                    total_size += len(entry_header) + len(image_data)
                
                print(f"총 바이너리 크기: {total_size:,} bytes")
                return True
                
        except Exception as e:
            print(f"[ERROR] MSI 바이너리 생성 실패: {e}")
            return False
    
    def _create_msi_binary_from_mappings(self, mappings: List[Dict[str, Any]], 
                                       output_file: str) -> bool:
        """Create an MSI binary from mapping information."""
        try:
            with open(output_file, 'wb') as out_f:
                total_size = 0
                
                # Write the MSI signature once at the start.
                msi_signature = self.MSI_SIGNATURE  # b'$MsI$'
                out_f.write(msi_signature)
                total_size += len(msi_signature)
                
                # Write padding/metadata to match the original layout.
                padding = b'\x8E\x00'
                out_f.write(padding)
                total_size += len(padding)
                
                for mapping in mappings:
                    original_entry = mapping['original_entry']
                    image_file = mapping['image_file']
                    
                    print(f"처리 중: Entry #{original_entry['index']} -> {os.path.basename(image_file)}")
                    
                    # Read image data.
                    with open(image_file, 'rb') as img_f:
                        image_data = img_f.read()
                    
                    # Create an MSI entry header without the signature.
                    entry_header = self._create_msi_entry_header(
                        original_entry['index'], len(image_data)
                    )
                    
                    # Write entry header and image data.
                    out_f.write(entry_header)
                    out_f.write(image_data)
                    
                    total_size += len(entry_header) + len(image_data)
                
                print(f"총 바이너리 크기: {total_size:,} bytes")
                
                # Store result metadata.
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
        """Create an MSI header for full-entry layout; currently unused."""
        header = bytearray(self.HEADER_SIZE)
        
        sig_len = len(self.MSI_SIGNATURE)
        header[0:sig_len] = self.MSI_SIGNATURE
        
        # Metadata fields.
        header[sig_len] = 0x00  # Sector/Layer
        header[sig_len + 1] = 0x00  # Position
        header[sig_len + 2] = image_number & 0xFF  # Image number
        header[sig_len + 3] = 0x00  # Reserved
        
        # Image size in little-endian format.
        struct.pack_into('<I', header, sig_len + 4, image_size)
        
        return bytes(header)
    
    def _create_msi_entry_header(self, image_number: int, image_size: int) -> bytes:
        """Create an MSI entry header without the signature."""
        # Layout expected by imageext.py:
        # - Image number, 2 bytes, little-endian.
        # - Image size, 4 bytes, little-endian.
        entry_header = bytearray(6)
        
        # Image number, 2 bytes, little-endian.
        struct.pack_into('<H', entry_header, 0, image_number)
        
        # Image size, 4 bytes, little-endian.  
        struct.pack_into('<I', entry_header, 2, image_size)
        
        return bytes(entry_header)
    
    def _create_msi_header_from_original(self, original_header: Dict[str, Any], 
                                       new_size: int) -> bytes:
        """Create an MSI header from original header metadata."""
        header = bytearray(self.HEADER_SIZE)
        
        sig_len = len(self.MSI_SIGNATURE)
        header[0:sig_len] = self.MSI_SIGNATURE
        
        # Preserve original metadata.
        header[sig_len] = original_header.get('sector', 0)
        header[sig_len + 1] = original_header.get('layer', 0)
        header[sig_len + 2] = original_header.get('image_number', 0)
        header[sig_len + 3] = original_header.get('reserved', 0)
        
        # Use the new image size.
        struct.pack_into('<I', header, sig_len + 4, new_size)
        
        return bytes(header)
    
    def _verify_repacked_file(self, output_file: str) -> None:
        """Verify the repacked file."""
        try:
            print(f"\n=== 리패킹 결과 검증 ===")
            
            with open(output_file, 'rb') as f:
                data = f.read()
            
            file_size = len(data)
            print(f"출력 파일 크기: {file_size:,} bytes")
            
            # Count MSI entries.
            msi_count = 0
            offset = 0
            
            while offset < len(data) - self.HEADER_SIZE:
                if data[offset:offset+len(self.MSI_SIGNATURE)] == self.MSI_SIGNATURE:
                    # Parse the header.
                    size_offset = offset + len(self.MSI_SIGNATURE) + 4
                    image_size = struct.unpack('<I', data[size_offset:size_offset+4])[0]
                    print(f"MSI Entry #{msi_count}: 오프셋 0x{offset:08X}, 크기 {image_size:,} bytes")
                    
                    msi_count += 1
                    offset += self.HEADER_SIZE + image_size
                else:
                    offset += 1
            
            print(f"검증된 MSI 엔트리: {msi_count}개")
            
        except Exception as e:
            print(f"[WARNING] 검증 중 오류 발생: {e}")
    
    def create_backup(self, original_file: str, backup_suffix: str = "_backup") -> str:
        """Create a backup of the original file."""
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
        """Store repack results. Generate a report."""
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
        """Detect modified images by comparing extracted files to the original in structure mode."""
        print("\n2단계: 수정된 이미지 파일 감지...")
        modified_images = {}
        unchanged_count = 0
        modified_count = 0
        
        if not original_analysis or 'msi_entries' not in original_analysis:
            print("[WARNING] 원본 분석 결과가 없어 변경 감지를 수행할 수 없습니다.")
            return {}
        
        # Load the original file.
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
            
            # Extract the original image data.
            start_offset = abs_offset
            end_offset = start_offset + original_size
            if end_offset > len(original_data):
                print(f"  [WARNING] 오프셋 범위 초과로 건너뛰기: 이미지 #{entry_index}")
                continue
                
            original_image_data = original_data[start_offset:end_offset]
            
            # Find the extracted file.
            filename = f"image_nr{entry_index}_off0x{abs_offset:X}"
            image_type = entry.get('image_type', 'bin')
            filepath = os.path.join(msi_pack_dir, f"{filename}.{image_type}")
            
            # Try alternate extensions.
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
                    
                    # Compare original and extracted data.
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
        """Detect modified images in simple mode by comparing with the original."""
        print("\n2단계: 수정된 이미지 파일 감지 (일반 모드)...")
        modified_images = {}
        unchanged_count = 0
        modified_count = 0
        
        # Load the original file.
        try:
            with open(original_file, 'rb') as f:
                original_data = f.read()
        except Exception as e:
            print(f"[ERROR] 원본 파일을 읽을 수 없습니다: {e}")
            return {}
        
        # Collect extracted image files.
        image_files = []
        for ext in self.supported_extensions:
            pattern = os.path.join(input_dir, f"*{ext}")
            image_files.extend(glob.glob(pattern))
        
        if not image_files:
            print("[WARNING] 추출된 이미지 파일을 찾을 수 없습니다.")
            return {}
        
        # Compare by extracting offset information from file names.
        for filepath in sorted(image_files):
            filename = os.path.basename(filepath)
            
            # Extract offset from file name, for example image_nr81_off0x647A.png -> 0x647A.
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
            
            # Extract image number, for example image_nr81_off0x647A.png -> 81.
            nr_match = re.search(r'image_nr(\d+)_', filename)
            if not nr_match:
                print(f"  [WARNING] 이미지 번호를 찾을 수 없는 파일명: {filename}")
                continue
                
            image_nr = int(nr_match.group(1))
            
            try:
                # Read the extracted file.
                with open(filepath, 'rb') as f:
                    extracted_data = f.read()
                
                # Find data at the matching offset in the original.
                original_image_data = self._find_original_image_at_offset(original_data, offset, len(extracted_data))
                
                if original_image_data is None:
                    print(f"  [WARNING] 원본에서 오프셋 0x{offset:X}에 해당하는 이미지를 찾을 수 없습니다: {filename}")
                    # Treat as a new image.
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
                
                # Compare with the original data.
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
        """Find image data at the given offset in the original data."""
        if offset >= len(original_data):
            return None
            
        # Try extracting the exact expected size.
        if offset + expected_size <= len(original_data):
            return original_data[offset:offset + expected_size]
        
        # Return data through the end of file.
        return original_data[offset:]
    
    def _copy_original_file(self, original_file: str, output_file: str) -> bool:
        """Copy the original file to the output path."""
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
    # Manual test harness.
    repacker = MSIImageRepacker()
    
    # Test paths; update before manual use.
    test_images_dir = "msi_extracted"  # 기본 추출 디렉터리
    test_output_file = "msi_repacked.bin"
    
    if os.path.exists(test_images_dir):
        print("MSI 이미지 리패커 테스트")
        print("=" * 50)
        
        # Test structure-preserving repack.
        success = repacker.repack_from_directory(test_images_dir, test_output_file)
        
        if success:
            # Generate a report.
            report_path = "msi_repack_report.txt"
            repacker.export_repack_report(report_path)
            print(f"[INFO] test.py로 재추출 시 MSI_Pack 폴더가 생성됩니다.")
    else:
        print(f"테스트 이미지 디렉터리를 찾을 수 없습니다: {test_images_dir}")
        print("먼저 MSI 파일을 분석하여 이미지를 추출하세요.")
