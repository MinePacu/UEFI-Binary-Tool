# 문제 해결

## GUI가 열리지 않음

`python3 gui_main.py` 실행 시 Tkinter가 없으면 자동으로 웹 UI로 전환됩니다. 터미널에 다음과 같은 주소가 표시되는지 확인하세요.

```text
UEFI Binary Tool 웹 UI: http://127.0.0.1:포트/
```

웹 UI도 열리지 않으면 브라우저에 해당 주소를 직접 입력합니다.

[터미널에 로컬 웹 UI 주소가 출력된 장면]

## 웹 UI에서 파일 선택 버튼이 없음

정상 동작입니다. 웹 UI는 브라우저 보안 제한 때문에 로컬 파일 경로를 자동으로 전달하지 않습니다. 전체 경로를 직접 입력하세요.

예:

```text
/Users/name/Desktop/bios.bin
C:\Users\name\Desktop\bios.bin
```

## `파일 경로가 비어 있습니다`

분석 또는 리패킹에 필요한 입력 경로가 비어 있습니다.

확인할 항목:

- 분석 탭의 `BIOS/Section 파일`
- 리패킹 탭의 `원본 BIOS 파일`
- 리패킹 탭의 `추출 이미지 디렉터리`
- 웹 UI 사용 시 전체 경로를 직접 입력했는지 여부

## `파일을 찾을 수 없습니다`

입력한 경로가 실제 파일을 가리키지 않습니다.

확인할 항목:

- 경로에 따옴표가 포함되어 있지 않은지
- 파일명이 정확한지
- Windows 경로에서 역슬래시가 빠지지 않았는지
- 디렉터리 경로와 파일 경로를 혼동하지 않았는지

## ASUS Packer 구조를 찾을 수 없음

오류 예:

```text
ASUS Packer 패키지 구조를 찾을 수 없습니다.
```

가능한 원인:

- 선택한 파일이 ASUS Packer Section Binary가 아님
- 전체 BIOS 이미지에서 필요한 Section을 추출하지 않은 상태임
- 파일이 손상되었거나 너무 작음
- MSI 파일을 ASUS 제조사로 선택함

해결:

- 제조사 선택을 확인합니다.
- ASUS Packer로 추출/리패킹 가능한 Section Binary인지 확인합니다.
- 원본 파일을 다시 준비합니다.

## MSI `$MsI$` 시그니처를 찾을 수 없음

오류 예:

```text
MSI Packer 시그니처 '$MsI$'를 찾을 수 없습니다.
```

가능한 원인:

- MSI Click BIOS X Section Binary가 아님
- Click BIOS 5 또는 다른 형식의 파일임
- ASUS 파일을 MSI 제조사로 선택함
- 전체 BIOS 이미지에서 대상 Section을 추출하지 않았음

해결:

- 제조사 선택을 확인합니다.
- MSI Click BIOS X 대상 Section인지 확인합니다.
- 별도 도구로 올바른 Section을 추출한 뒤 다시 분석합니다.

## ASUS 리패킹에서 이미지가 건너뛰어짐

가능한 원인:

- 파일명이 `image_nr{번호}_off0x{오프셋}.{확장자}` 규칙과 다름
- 원본 이미지 타입과 수정 이미지 타입이 다름
- `asus_pack_1`, `asus_pack_2` 등 패키지 폴더가 누락됨

해결:

- 추출 당시 파일명을 유지합니다.
- PNG는 PNG로, BMP는 BMP로 같은 컨테이너 형식을 유지합니다.
- `asus_extracted/asus_pack_*` 구조를 확인합니다.

## MSI 리패킹할 이미지 파일을 찾을 수 없음

가능한 원인:

- 입력 디렉터리가 비어 있음
- 지원 확장자가 아님
- `MSI_pack*` 하위 폴더 위치가 잘못됨

지원 확장자:

```text
.bin, .jpg, .jpeg, .png, .bmp, .ico
```

해결:

- `msi_extracted/MSI_pack_*` 폴더 안에 이미지 파일이 있는지 확인합니다.
- 일반 모드라면 지정한 입력 디렉터리 바로 아래에 이미지 파일이 있는지 확인합니다.

## 리패킹 결과가 원본과 동일함

수정된 이미지가 없다고 판단되면 프로그램은 원본 파일을 그대로 복사합니다.

확인할 항목:

- 실제 이미지 파일을 수정했는지
- 수정 파일을 올바른 추출 폴더에 저장했는지
- 파일명이 원본 매핑 규칙을 유지하는지
- 원본과 수정본이 바이트 단위로 동일하지 않은지

## 생성 파일 위치를 찾기 어려움

작업 완료 후 GUI의 작업 로그에서 `[OUTPUTS]` 또는 `[OUTPUT]` 아래를 확인하세요.

일반적인 생성 파일:

```text
*_analysis.txt
*_analysis.md
*_msi_analysis_report.txt
*_asus_repacked.bin
*_msi_repacked.bin
*_repack_report.txt
```

[작업 로그 하단에 출력 파일 목록이 표시된 장면]
