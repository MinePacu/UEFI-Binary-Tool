# BIOS Section Binary 분석/Emebedded Image 리패킹 통합 도구

메인보드의 BIOS/UEFI의 Section 바이너리 파일을 분석하고 리패킹하는 Python 기반 도구입니다.

## 📋 개요

이 도구는 메인보드의 BIOS/UEFI 내에 있는 Section을 분석하여 내부 구조를 파악하고, 임베디드 이미지를 다시 패키징할 수 있느 솔루션입니다.

## 🚀 주요 기능

- **Section Binary 파일 분석**: 매직 바이트 패턴 검출 및 구조 분석
- **이미지 리패킹**: 수정된 이미지를 각 제조사의 Packer 형식으로 패키징

## 🛠️ 설치 및 요구사항

### 시스템 요구사항
- Python 3.6 이상
- Windows/Linux/macOS

### 의존성
- 표준 라이브러리만 사용 (추가 설치 불필요)
  - `os`, `sys`, `struct`, `re`, `binascii`
  - `collections`, `datetime`

## 🎯 사용법

### 1. Windows에서 배치 파일 실행
```bash
asus_tools.bat
```

### 2. Python 직접 실행

#### 대화형 모드
```bash
python asus_main.py
```

#### 명령줄 모드
```bash
# 파일 분석
python asus_main.py analyze [파일경로]

# 이미지 리패킹
python asus_main.py repack [파일경로]
```

#### 드래그 앤 드롭
BIOS 파일을 `asus_tools.bat`로 직접 드래그하여 실행할 수 있습니다.

## 🔧 지원 형식

### 입력 형식
- Section 패키지 (.bin)
- UEFI 펌웨어 볼륨
- PE/DOS 실행 파일
- 기타 바이너리 이미지

### 출력 형식
- 재패키징된 Section Binary 파일
- 분석 리포트 (텍스트)

## 📝 사용 예시

### 1. BIOS 파일 분석
```
[ANALYZE] ASUS BIOS 파일 분석 모드
==================================================
분석할 파일: bios_image.bin
파일 크기: 16,777,216 bytes (16.00 MB)

=== 매직 바이트 분석 ===
오프셋 0x00000000: MZ (PE/DOS Executable)
오프셋 0x00000800: _FVH (UEFI Firmware Volume)
```

### 2. 이미지 리패킹
```
[REPACK] ASUS 이미지 리패킹 모드
==================================================
원본 파일: original_bios.bin
추출 디렉터리: asus_extracted/
출력 파일: original_bios_asus_repacked.bin

[SUCCESS] 리패킹이 완료되었습니다.
```

## ⚠️ 주의사항

1. **백업 필수**: 원본 BIOS 파일을 반드시 백업하세요
2. **호환성**: ASUS 메인보드 전용 도구입니다. 추후 다른 제조사 바이오스도 지원하기 위해 노력 중입니다.
3. **검증**: 리패킹된 파일을 플래시하기 전에 충분히 검증하세요.
## 🐛 문제 해결

### 일반적인 오류
- **모듈 import 오류**: Python 경로 설정 확인
- **파일 접근 오류**: 파일 권한 및 경로 확인

### 디버깅
프로그램은 상세한 오류 메시지와 진행 상황을 출력합니다. 문제 발생 시 출력 메시지를 확인하세요.

## 📁 프로젝트 구조

```
program/
├── asus_main.py           # 메인 프로그램 (진입점)
├── asus_tools.bat         # Windows 배치 실행 스크립트
├── asus/                  # ASUS 관련 모듈
│   ├── analyzer/
│   │   └── asus_analyzer.py    # BIOS 파일 분석기
│   └── repacker/
│       └── asus_repacker.py    # 이미지 리패커
└── common/                # 공통 유틸리티
    └── file_utils.py      # 파일 처리 유틸리티
```

## 📖 모듈 상세 설명

### `asus_main.py`
- **역할**: 프로그램의 진입점 및 메인 컨트롤러
- **기능**:
  - 사용자 인터페이스 제공 (대화형/명령줄)
  - 각 모드별 작업 조정
  - 파일 경로 검증 및 처리

### `asus/analyzer/asus_analyzer.py`
- **역할**: ASUS BIOS 파일 분석
- **주요 클래스**: `AsusFileAnalyzer`
- **기능**:
  - 매직 바이트 패턴 감지
  - UEFI 구조 분석
  - ASUS Packer 형식 식별
  - 파일 구조 시각화

### `asus/repacker/asus_repacker.py`
- **역할**: 이미지 리패킹
- **주요 클래스**: `AsusImageRepacker`
- **기능**:
  - ASUS Packer 형식 감지
  - 추출된 이미지 재패키징
  - 메타데이터 보존
  - 구조 무결성 검증

### `common/file_utils.py`
- **역할**: 공통 파일 처리 유틸리티
- **기능**:
  - 파일 경로 입력 및 검증
  - 명령줄 인수 처리
  - 디렉터리 생성 및 관리
  - 출력 파일명 생성

## 🤝 기여

버그 리포트나 기능 제안은 이슈로 등록해 주세요.

---

**⚡ 빠른 시작**: `asus_tools.bat`를 실행하거나 BIOS 파일을 `asus_tools.bat`로 드래그하세요!
