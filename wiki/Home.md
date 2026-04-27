# UEFI Binary Tool Wiki

> 이 문서는 현재 프로그램 상태를 기준으로 작성되었습니다.
> 스크린샷은 직접 추가할 수 있도록 필요한 위치에 `[...하는 장면]` 형식으로 표시했습니다.

## 개요

UEFI Binary Tool은 BIOS/UEFI Section 바이너리에서 ASUS Packer 또는 MSI Packer 구조를 분석하고, 외부에서 수정한 이미지 파일을 다시 패키징하는 도구입니다.

현재 지원 범위는 다음과 같습니다.

| 제조사 | 지원 기능 | 비고 |
|---|---|---|
| ASUS | Section Binary 분석, ASUS Packer 구조 기반 이미지 리패킹 | 리패킹에는 원본 BIOS/Section 파일과 `asus_extracted/asus_pack_*` 형태의 추출 폴더가 필요합니다. |
| MSI | MSI Click BIOS X Section Binary 분석, 이미지 리패킹 | 프로그램 자체는 MSI 이미지 추출 기능을 제공하지 않습니다. 추출 폴더는 별도 도구로 준비해야 합니다. |

## 빠른 시작

GUI 실행:

```bash
python3 gui_main.py
```

또는:

```bash
python3 -m uefi_binary_tool
```

Tkinter가 설치된 Python에서는 데스크톱 GUI가 열립니다. Tkinter가 없는 환경에서는 로컬 웹 UI가 자동으로 실행되고 브라우저가 열립니다.

[프로그램을 처음 실행했을 때 제조사 선택, 분석 탭, 리패킹 탭, 작업 로그 영역이 보이는 장면]

## 권장 문서 순서

1. [GUI 사용법](GUI-Usage)
2. [ASUS 분석 및 리패킹](ASUS-Workflow)
3. [MSI 분석 및 리패킹](MSI-Workflow)
4. [CLI 및 Windows 배치 파일](CLI-and-Batch)
5. [문제 해결](Troubleshooting)

## 중요한 주의사항

- 원본 BIOS/UEFI 파일은 반드시 별도로 백업하세요.
- 리패킹 결과물을 실제 플래시에 사용하기 전, 별도의 검증 절차를 거치세요.
- 제조사와 형식이 맞지 않는 파일은 분석 또는 리패킹 전에 검증 단계에서 거부될 수 있습니다.
- MSI는 Click BIOS X 형식의 `$MsI$` Packer 엔트리를 대상으로 합니다.
- 이 도구의 리패킹 기능은 이미지 교체와 구조 보존을 돕는 도구이며, 결과 파일의 실제 하드웨어 적용 가능성을 보장하지 않습니다.
