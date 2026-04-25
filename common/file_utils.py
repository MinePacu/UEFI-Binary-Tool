#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Common file utility module
Shared helpers for file paths, validation, and basic I/O.
"""

import os
import sys


def get_file_path_input(prompt, default_path=None):
    """Prompt the user for a file path."""
    if default_path and os.path.exists(default_path):
        print(f"기본 파일: {os.path.basename(default_path)}")
        print(f"경로: {default_path}")
        user_input = input(f"{prompt} (엔터시 기본 파일 사용): ").strip()
        if not user_input:
            return default_path
        file_path = user_input
    else:
        file_path = input(f"{prompt}: ").strip()
    
    # Strip quotes added by drag-and-drop input.
    file_path = file_path.strip('"').strip("'")
    
    return file_path


def get_file_path(prompt, default_path=None):
    """Compatibility alias for the existing MSI entry point."""
    return get_file_path_input(prompt, default_path)


def validate_file_path(file_path):
    """Validate the file path."""
    if not file_path:
        print("오류: 파일 경로가 입력되지 않았습니다.")
        return False
    
    if not os.path.exists(file_path):
        print(f"오류: 파일을 찾을 수 없습니다")
        print(f"경로: {file_path}")
        print("파일 경로를 다시 확인해주세요.")
        return False
    
    if not os.path.isfile(file_path):
        print(f"오류: 지정된 경로가 파일이 아닙니다")
        print(f"경로: {file_path}")
        return False
    
    return True


def get_command_line_file():
    """Extract a file path from command-line arguments."""
    if len(sys.argv) > 1:
        # A file was provided by drag and drop.
        file_path = sys.argv[1].strip('"').strip("'")
        print(f"📁 전달된 파일: {os.path.basename(file_path)}")
        
        # Validate the file path.
        if not validate_file_path(file_path):
            return None
            
        print(f"✓ 드래그 앤 드롭으로 선택된 파일: {os.path.basename(file_path)}")
        print(f"  경로: {file_path}")
        print(f"  크기: {os.path.getsize(file_path):,} bytes\n")
        return file_path
    
    return None


def ensure_directory_exists(directory_path):
    """Create the directory when it does not exist."""
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)
        print(f"✓ 디렉터리 생성: {directory_path}")
    return True


def get_output_filename(base_path, suffix, extension=".bin"):
    """Build an output file name."""
    base_name = os.path.splitext(os.path.basename(base_path))[0]
    output_dir = os.path.dirname(base_path)
    return os.path.join(output_dir, f"{base_name}_{suffix}{extension}")


def create_output_filename(base_path, suffix, extension=".bin"):
    """Compatibility alias for existing output file name callers."""
    return get_output_filename(base_path, suffix, extension)
