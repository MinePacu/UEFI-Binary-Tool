# CLI 및 Windows 배치 파일

## GUI 실행 명령

```bash
python3 gui_main.py
```

또는:

```bash
python3 -m uefi_binary_tool
```

## ASUS CLI

대화형 모드:

```bash
python3 asus_main.py
```

분석:

```bash
python3 asus_main.py analyze /path/to/asus_section.bin
```

리패킹:

```bash
python3 asus_main.py repack /path/to/original_asus_section.bin
```

ASUS 리패킹 CLI는 실행 중 추출 디렉터리와 출력 파일명을 입력받습니다.

[터미널에서 `python3 asus_main.py` 실행 후 ASUS 메뉴가 표시된 장면]

## MSI CLI

대화형 모드:

```bash
python3 msi_main.py
```

분석:

```bash
python3 msi_main.py analyze /path/to/msi_section.bin
```

리패킹:

```bash
python3 msi_main.py repack /path/to/msi_extracted
```

MSI 리패킹 CLI는 입력 디렉터리 주변에서 원본 `.bin` 파일을 자동으로 찾으려고 시도합니다. 원본 파일을 찾으면 원본 분석 결과를 사용해 변경 감지와 구조 보존을 수행합니다.

[터미널에서 `python3 msi_main.py analyze bios.bin` 실행 후 MSI Entry 목록이 표시된 장면]

## Windows 배치 파일

Windows에서는 `batch` 폴더의 배치 파일을 사용할 수 있습니다.

ASUS:

```bat
batch\asus_tools.bat
```

MSI:

```bat
batch\msi_tools.bat
```

배치 파일은 다음을 먼저 확인합니다.

- Python 실행 가능 여부
- 필요한 Python 파일 존재 여부
- 메뉴 선택 또는 드래그 앤 드롭으로 전달된 파일 존재 여부

[Windows 명령 프롬프트에서 ASUS 배치 파일 메뉴가 표시된 장면]

## 배치 파일 드래그 앤 드롭

ASUS:

- BIOS/Section 파일을 `batch\asus_tools.bat`로 드래그합니다.
- 메뉴에서 분석 또는 리패킹을 선택합니다.
- 리패킹 시 추출 디렉터리 경로를 입력합니다.

MSI:

- MSI `.bin` 파일을 `batch\msi_tools.bat`로 드래그합니다.
- 분석 메뉴는 전달된 파일을 사용합니다.
- 리패킹 메뉴는 기본적으로 프로젝트 루트의 `msi_extracted` 폴더를 사용합니다.

[BIOS 파일을 Windows 배치 파일 위로 드래그하는 장면]

## 언어 강제 지정

배치 파일도 `UEFI_BINARY_TOOL_LANG` 환경 변수를 사용할 수 있습니다.

한국어:

```bat
set UEFI_BINARY_TOOL_LANG=ko
batch\asus_tools.bat
```

영어:

```bat
set UEFI_BINARY_TOOL_LANG=en
batch\msi_tools.bat
```
