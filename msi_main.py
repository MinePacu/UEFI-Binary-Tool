#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Main entry point for MSI BIOS Section Binary analysis/repack operations

Analyzes MSI motherboard BIOS/UEFI Section binary files and 
repackages images. Extraction is intentionally out of scope.
"""

import os
import sys
import argparse
from typing import Optional

# Enable UTF-8 console output on Windows.
if os.name == 'nt':  # Windows
    import locale
    try:
        # Configure Windows console encoding.
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except:
        # Compatibility path for Python 3.6 and older.
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.detach())

# Import shared modules.
try:
    sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
    from common.file_utils import get_file_path, validate_file_path, create_output_filename
except ImportError:
    print("[WARNING] 공통 모듈을 찾을 수 없습니다. 기본 기능만 사용합니다.")

# Import MSI modules.
from msi.analyzer.msi_analyzer import MSIFileAnalyzer
from msi.repacker.msi_repacker import MSIImageRepacker


class MSIMainController:
    """Main controller for MSI tool workflows."""
    
    def __init__(self):
        """Initialize instance state."""
        self.analyzer = MSIFileAnalyzer()
        self.repacker = MSIImageRepacker()
        
    def run_interactive(self):
        """Run interactive mode."""
        print("=" * 60)
        print("     MSI BIOS Section Binary 분석/리패킹 도구")
        print("=" * 60)
        print()
        print("지원 기능:")
        print("1. MSI BIOS 파일 분석")
        print("2. 이미지 리패킹")
        print("3. 종료")
        print()
        
        while True:
            try:
                choice = input("선택하세요 (1-3): ").strip()
                
                if choice == '1':
                    self._interactive_analyze()
                elif choice == '2':
                    self._interactive_repack()
                elif choice == '3':
                    print("프로그램을 종료합니다.")
                    break
                else:
                    print("잘못된 선택입니다. 1-3 중에서 선택하세요.")
                    
            except KeyboardInterrupt:
                print("\n\n프로그램을 종료합니다.")
                break
            except Exception as e:
                print(f"[ERROR] 처리 중 오류 발생: {e}")
    
    def _interactive_analyze(self):
        """Run interactive analysis mode."""
        print("\n=== MSI BIOS 파일 분석 ===")
        
        file_path = self._get_input_file("분석할 MSI BIOS 파일을 입력하세요")
        if not file_path:
            return
        
        # Analyze the file.
        results = self.analyzer.analyze_file(file_path)
        
        if results:
            # Ask whether to save the report.
            save_report = input("\n분석 리포트를 저장하시겠습니까? (y/n): ").strip().lower()
            if save_report in ['y', 'yes']:
                report_path = f"{os.path.splitext(file_path)[0]}_msi_analysis_report.txt"
                self.analyzer.export_analysis_report(report_path)
    
    def _interactive_repack(self):
        """Run interactive repack mode."""
        print("\n=== MSI 이미지 리패킹 ===")
        
        # Validate the input directory.
        input_dir = input("리패킹할 이미지 디렉터리를 입력하세요: ").strip()
        if not input_dir or not os.path.exists(input_dir):
            print("[ERROR] 유효한 디렉터리를 입력해주세요.")
            return
        
        # Resolve the output file name.
        default_output = f"{input_dir}_msi_repacked.bin"
        output_file = input(f"출력 파일명 ({default_output}): ").strip()
        if not output_file:
            output_file = default_output
        
        # Ask whether to use original analysis data.
        use_analysis = input("원본 분석 결과를 사용하시겠습니까? (y/n): ").strip().lower()
        
        if use_analysis in ['y', 'yes']:
            # Original file is required for this path.
            original_file = input("원본 MSI BIOS 파일 경로를 입력하세요: ").strip()
            if original_file and os.path.exists(original_file):
                print("원본 파일을 분석 중...")
                results = self.analyzer.analyze_file(original_file)
                if results:
                    success = self.repacker.repack_from_analysis(results, input_dir, output_file)
                else:
                    print("[ERROR] 원본 파일 분석에 실패했습니다.")
                    return
            else:
                print("[ERROR] 유효한 원본 파일을 입력해주세요.")
                return
        else:
            # Run normal repack; structure-preservation mode is auto-detected.
            success = self.repacker.repack_from_directory(input_dir, output_file)
        
        if success:
            print(f"\n리패킹이 완료되었습니다: {output_file}")
            
            # Save the report.
            report_path = f"{os.path.splitext(output_file)[0]}_repack_report.txt"
            self.repacker.export_repack_report(report_path)
    
    def _get_input_file(self, prompt: str) -> Optional[str]:
        """Get an input file path."""
        try:
            file_path = get_file_path(prompt)
            if validate_file_path(file_path):
                return file_path
        except:
            # Fallback prompt when shared helpers are unavailable.
            file_path = input(f"{prompt}: ").strip()
            if file_path and os.path.exists(file_path):
                return file_path
            else:
                print("[ERROR] 유효한 파일 경로를 입력해주세요.")
        
        return None
    
    def run_full_process(self, file_path: str):
        """Integrated drag-and-drop workflow: analyze and repack."""
        print(f"[FULL PROCESS] MSI BIOS 파일 통합 처리")
        print("=" * 60)
        print(f"처리할 파일: {os.path.basename(file_path)}")
        print("주의: 추출된 이미지 폴더(msi_extracted)가 미리 존재해야 합니다.")
        print()
        
        if not os.path.exists(file_path):
            print(f"[ERROR] 파일을 찾을 수 없습니다: {file_path}")
            return
        
        try:
            # Step 1: analyze the file.
            print("🔍 1단계: MSI BIOS 파일 분석 중...")
            results = self.analyzer.analyze_file(file_path)
            
            if not results or not results.get('msi_entries'):
                print("[ERROR] MSI 엔트리를 찾을 수 없습니다. MSI 형식이 아닌 것 같습니다.")
                return
            
            # Step 2: locate an existing extracted folder.
            print("\n� 2단계: 추출된 이미지 폴더 확인 중...")
            current_dir = os.path.dirname(file_path) if os.path.dirname(file_path) else os.getcwd()
            default_extract_dir = os.path.join(current_dir, "msi_extracted")
            
            # Check whether the default path contains an MSI_Pack folder.
            if os.path.exists(default_extract_dir):
                msi_pack_folders = [d for d in os.listdir(default_extract_dir) 
                                  if os.path.isdir(os.path.join(default_extract_dir, d)) and d.startswith("MSI_pack_")]
                if msi_pack_folders:
                    extract_dir = default_extract_dir
                    print(f"기존 추출 폴더를 발견했습니다: {extract_dir}")
                else:
                    print(f"[ERROR] 추출된 이미지 폴더를 찾을 수 없습니다: {default_extract_dir}")
                    print("MSI 파일을 먼저 추출해주세요 (별도의 추출 도구 사용)")
                    return
            else:
                print(f"[ERROR] 추출된 이미지 폴더를 찾을 수 없습니다: {default_extract_dir}")
                print("MSI 파일을 먼저 추출해주세요 (별도의 추출 도구 사용)")
                return
            
            # Step 3: repack while preserving original structure.
            print("\n📦 3단계: 원본 구조 유지 리패킹 중...")
            
            # Build the repacked output file name.
            base_name = os.path.splitext(os.path.basename(file_path))[0]
            repacked_file = os.path.join(current_dir, f"{base_name}_msi_repacked.bin")
            
            # Run structure-preserving repack using original analysis data.
            repack_success = self.repacker.repack_from_directory(
                extract_dir, repacked_file, original_analysis=results
            )
            
            if repack_success:
                print(f"\n✅ 통합 처리 완료!")
                print(f"원본 파일: {file_path}")
                print(f"사용된 추출 폴더: {extract_dir}")
                print(f"리패킹 파일: {repacked_file}")
                
                # Save the analysis report.
                report_path = os.path.join(current_dir, f"{base_name}_msi_analysis_report.txt")
                self.analyzer.export_analysis_report(report_path)
                
                print(f"\n📋 생성된 파일들:")
                print(f"  - 분석 리포트: {report_path}")
                print(f"  - 리패킹된 BIOS: {repacked_file}")
                
                print(f"\n💡 참고사항:")
                print(f"  - 원본 구조와 메타데이터가 완전히 보존되었습니다")
                
            else:
                print("[ERROR] 리패킹에 실패했습니다.")
                
        except Exception as e:
            print(f"[ERROR] 통합 처리 중 오류 발생: {e}")
            import traceback
            traceback.print_exc()
    
    def run_analyze(self, file_path: str = None):
        """Run analysis mode."""
        print(f"[ANALYZE] MSI BIOS 파일 분석 모드")
        print("=" * 50)
        
        # Prompt interactively when no file path is provided.
        if not file_path:
            file_path = self._get_input_file("분석할 MSI BIOS 파일을 입력하세요")
            if not file_path:
                return
        
        if not os.path.exists(file_path):
            print(f"[ERROR] 파일을 찾을 수 없습니다: {file_path}")
            return
        
        # Analyze the file.
        results = self.analyzer.analyze_file(file_path)
        
        if results:
            # Save the report automatically.
            report_path = f"{os.path.splitext(file_path)[0]}_msi_analysis_report.txt"
            self.analyzer.export_analysis_report(report_path)
            print(f"\n[INFO] 분석 리포트가 저장되었습니다: {report_path}")
    
    def run_repack(self, input_path: str = None):
        """Run repack mode."""
        print(f"[REPACK] MSI 이미지 리패킹 모드")
        print("=" * 50)
        
        # Prompt interactively when no input path is provided.
        if not input_path:
            print("리패킹할 디렉터리를 선택하세요.")
            print("일반적으로 msi_extracted 폴더를 선택합니다.")
            input_path = input("디렉터리 경로: ").strip().strip('"')
            if not input_path:
                print("[ERROR] 디렉터리 경로가 입력되지 않았습니다.")
                return
        
        if not os.path.exists(input_path):
            print(f"[ERROR] 경로를 찾을 수 없습니다: {input_path}")
            return
        
        # Resolve the output file name.
        if os.path.isdir(input_path):
            output_file = f"{input_path}_msi_repacked.bin"
        else:
            output_file = f"{os.path.splitext(input_path)[0]}_msi_repacked.bin"
        
        # Repack from a directory.
        # Find the original file for change detection.
        original_file = self._find_original_file(input_path)
        original_analysis = None
        
        if original_file:
            print(f"원본 파일 발견: {original_file}")
            # Load analysis results for the original file.
            original_analysis = self.analyzer.analyze_file(original_file)
            if not original_analysis:
                print("[ERROR] 원본 파일이 유효한 MSI Packer 형식이 아니므로 리패킹을 중단합니다.")
                return
            
        success = self.repacker.repack_from_directory(
            input_path, output_file, 
            preserve_order=True, 
            original_analysis=original_analysis,
            original_file=original_file
        )
        
        if success:
            print(f"\n[SUCCESS] 리패킹 완료: {output_file}")
            
            # Save the report.
            report_path = f"{os.path.splitext(output_file)[0]}_repack_report.txt"
            self.repacker.export_repack_report(report_path)
    
    def _find_original_file(self, input_path: str) -> str:
        """Find the original file from the repack input path."""
        if not os.path.isdir(input_path):
            return None
            
        # If input is msi_extracted, look for a .bin file beside it.
        parent_dir = os.path.dirname(os.path.abspath(input_path))
        if not parent_dir or parent_dir == input_path:
            parent_dir = os.getcwd()
            
        if os.path.basename(input_path) == 'msi_extracted':
            if os.path.exists(parent_dir):
                for file in os.listdir(parent_dir):
                    if file.endswith('.bin') and not file.endswith('_repacked.bin'):
                        original_file = os.path.join(parent_dir, file)
                        if os.path.isfile(original_file):
                            return original_file
        
        # If MSI_pack folders exist, look for the original in the parent directory.
        try:
            if any(d.startswith('MSI_pack') for d in os.listdir(input_path) if os.path.isdir(os.path.join(input_path, d))):
                if os.path.exists(parent_dir):
                    for file in os.listdir(parent_dir):
                        if file.endswith('.bin') and not file.endswith('_repacked.bin'):
                            original_file = os.path.join(parent_dir, file)
                            if os.path.isfile(original_file):
                                return original_file
        except:
            pass
        
        return None


def main():
    """Program entry point."""
    parser = argparse.ArgumentParser(
        description="MSI BIOS Section Binary 분석/리패킹 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage examples:
  python msi_main.py                          # interactive mode
  python msi_main.py analyze bios.bin         # analyze a BIOS file
  python msi_main.py repack extracted_dir/    # repack images
        """
    )
    
    parser.add_argument(
        'mode', 
        nargs='?',
        choices=['analyze', 'repack'],
        help='실행 모드 (analyze/repack)'
    )
    
    parser.add_argument(
        'input_path',
        nargs='?',
        help='입력 파일 또는 디렉터리 경로'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='MSI BIOS 도구 v1.0.0'
    )
    
    # Support drag-and-drop invocation.
    if len(sys.argv) == 2 and os.path.exists(sys.argv[1]):
        # A file was passed by drag and drop.
        file_path = sys.argv[1]
        print(f"드래그된 파일 감지: {file_path}")
        
        controller = MSIMainController()
        
        # Choose mode automatically from file extension.
        if file_path.lower().endswith('.bin'):
            print("MSI BIOS 파일로 판단하여 통합 처리를 시작합니다...")
            controller.run_full_process(file_path)
        else:
            print("알 수 없는 파일 형식입니다. 분석 모드로 시작합니다.")
            controller.run_analyze(file_path)
        
        input("\n계속하려면 Enter 키를 누르세요...")
        return
    
    args = parser.parse_args()
    controller = MSIMainController()
    
    try:
        if not args.mode:
            # Run interactive mode.
            controller.run_interactive()
        elif args.mode == 'analyze':
            # Menu-driven calls may omit input_path.
            controller.run_analyze(args.input_path)
        elif args.mode == 'repack':
            # Menu-driven calls may omit input_path.
            controller.run_repack(args.input_path)
            
    except KeyboardInterrupt:
        print("\n\n프로그램이 중단되었습니다.")
    except Exception as e:
        print(f"[ERROR] 예상치 못한 오류 발생: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
