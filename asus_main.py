#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ASUS BIOS 이미지 분석/추출/리패킹 통합 도구
메인보드 제조사별 분류 시스템의 ASUS 모듈
"""

import os
import sys

# 현재 스크립트의 디렉터리를 Python 경로에 추가
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# 모듈 import
try:
    from common.file_utils import get_file_path_input, validate_file_path, get_command_line_file
    from asus.analyzer.asus_analyzer import AsusFileAnalyzer
    from asus.repacker.asus_repacker import AsusImageRepacker
except ImportError as e:
    print(f"모듈 import 오류: {e}")
    print("필요한 모듈 파일들이 올바른 위치에 있는지 확인하세요.")
    sys.exit(1)


def print_banner():
    """프로그램 배너 출력"""
    print("=" * 70)
    print("           ASUS BIOS 이미지 분석/리패킹 통합 도구 v3.0")
    print("=" * 70)
    print("제조사: ASUS")
    print("지원 형식: ASUS Packer, UEFI 이미지")
    print("기능: 분석, 리패킹")
    print("=" * 70)


def get_target_file(provided_file=None):
    """대상 파일 경로 확인 및 반환"""
    file_path = provided_file
    
    if file_path is None:
        # 명령줄 인수 확인
        file_path = get_command_line_file()
    
    if file_path is None:
        # 기본 파일 경로 (현재 프로그램 디렉터리에 있는 파일)
        default_file_path = os.path.join(current_dir, "Section_Raw_CC5840D2-D8EA-459E-BAF4-349AC710EBBE_body.bin")
        
        # 사용자로부터 파일 경로 입력받기
        print("분석할 ASUS BIOS 파일을 선택하세요.")
        file_path = get_file_path_input("분석할 파일의 전체 경로를 입력하세요", default_file_path)
        
        # 파일 경로 유효성 검사
        if not validate_file_path(file_path):
            return None
        
        print(f"[OK] 선택된 파일: {os.path.basename(file_path)}")
        print(f"  경로: {file_path}")
        print(f"  크기: {os.path.getsize(file_path):,} bytes\n")
    
    return file_path


def analyze_mode(file_path=None):
    """ASUS 파일 분석 모드"""
    print("\n[ANALYZE] ASUS 파일 분석 모드")
    print("=" * 50)
    
    target_file = get_target_file(file_path)
    if not target_file:
        return False
    
    try:
        analyzer = AsusFileAnalyzer(target_file)
        analyzer.run_full_analysis()
        return True
        
    except Exception as e:
        print(f"[ERROR] 분석 중 오류 발생: {e}")
        return False


def repack_mode(file_path=None):
    """ASUS 이미지 리패킹 모드"""
    print("\n[REPACK] ASUS 이미지 리패킹 모드")
    print("=" * 50)
    
    target_file = get_target_file(file_path)
    if not target_file:
        return False
    
    try:
        # 추출된 ASUS 이미지 디렉터리 경로 입력받기
        default_extracted_dir = os.path.join(os.path.dirname(file_path), "asus_extracted")
        print(f"\nASUS Packer로 추출된 이미지 파일들이 있는 디렉터리를 지정하세요.")
        extracted_dir = get_file_path_input("ASUS 추출 디렉터리 경로를 입력하세요", default_extracted_dir)
        
        if not os.path.exists(extracted_dir):
            print(f"오류: 추출된 파일 디렉터리를 찾을 수 없습니다.")
            print(f"경로: {extracted_dir}")
            return False
        
        # 출력 파일명 설정
        output_file = input("출력 파일명을 입력하세요 (엔터시 자동 생성): ").strip()
        if not output_file:
            base_name = os.path.splitext(os.path.basename(target_file))[0]
            output_dir = os.path.dirname(target_file)
            output_file = os.path.join(output_dir, f"{base_name}_asus_repacked.bin")
        
        # 구조 보존 옵션
        
        repacker = AsusImageRepacker(target_file)
        success = repacker.run_repack(extracted_dir, output_file)
        
        if success:
            print(f"\n[SUCCESS] 리패킹이 완료되었습니다.")
            print(f"[OUTPUT] 출력 파일: {output_file}")
            return True
        else:
            print("[ERROR] 리패킹이 실패했습니다.")
            return False
        
    except Exception as e:
        print(f"[ERROR] 리패킹 중 오류 발생: {e}")
        return False

def interactive_mode():
    """대화형 모드"""
    print_banner()
    
    while True:
        print("\n[MENU] ASUS BIOS 도구 메인 메뉴")
        print("=" * 50)
        print("1. [ANALYZE] ASUS BIOS 파일 분석")
        print("2. [REPACK] ASUS 이미지 리패킹")
        print("3. [EXIT] 종료")
        print("=" * 50)

        choice = input("선택하세요 (1-3): ").strip()

        if choice == "1":
            analyze_mode()
        elif choice == "2":
            repack_mode()
        elif choice == "3":
            print("\n프로그램을 종료합니다.")
            break
        else:
            print("[ERROR] 잘못된 선택입니다. 1-3 중에서 선택해주세요.")
        
        print("\n" + "-" * 70)
        continue_choice = input("다른 작업을 수행하시겠습니까? (y/n): ").lower().strip()
        if continue_choice not in ['y', 'yes', '예']:
            print("\n프로그램을 종료합니다.")
            break


def main():
    """메인 함수"""
    if len(sys.argv) < 2:
        # 인수가 없으면 대화형 모드
        interactive_mode()
        return
    
    mode = sys.argv[1].lower()
    file_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    print_banner()
    
    success = False
    
    if mode == "analyze":
        success = analyze_mode(file_path)
    elif mode == "repack":
        success = repack_mode(file_path)
    else:
        print(f"[ERROR] 알 수 없는 모드: {mode}")
        print("사용법: python asus_main.py [analyze|extract|repack|integrated] [파일경로]")
        sys.exit(1)
    
    if success:
        print("\n[SUCCESS] 작업이 성공적으로 완료되었습니다!")
        sys.exit(0)
    else:
        print("\n[ERROR] 작업이 실패했습니다.")
        sys.exit(1)


if __name__ == "__main__":
    main()
