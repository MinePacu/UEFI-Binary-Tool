# MSI 분석 및 리패킹

## 지원 범위

MSI 워크플로는 MSI Click BIOS X Section Binary의 `$MsI$` Packer 구조를 대상으로 합니다.

현재 프로그램은 MSI 이미지 추출 기능을 제공하지 않습니다. 리패킹하려면 별도 도구로 추출한 이미지 디렉터리를 먼저 준비해야 합니다.

## MSI 파일 분석

GUI에서 실행:

1. 제조사를 `MSI`로 선택합니다.
2. `분석` 탭을 엽니다.
3. 분석할 MSI BIOS/Section 파일을 선택합니다.
4. `분석 시작`을 누릅니다.

[MSI 분석 실행 후 작업 로그에 `$MsI$` 시그니처 수와 MSI Entry 목록이 표시된 장면]

CLI에서 실행:

```bash
python3 msi_main.py analyze /path/to/msi_section.bin
```

분석 과정에서 확인하는 항목:

- `$MsI$` 시그니처 존재 여부
- MSI Packer 엔트리 구조
- 엔트리별 오프셋, 이미지 크기, 이미지 번호
- 이미지 타입 추정
- 매직 바이트 패턴
- 엔트리 수, 총 이미지 크기, 파일 커버리지

생성 파일:

```text
<원본파일명>_msi_analysis_report.txt
```

## MSI 리패킹 준비

리패킹 입력은 추출된 이미지 파일이 들어 있는 디렉터리입니다.

구조 보존 모드에서 권장되는 폴더 구조:

```text
msi_extracted/
└── MSI_pack_1/
    ├── image_nr0_off0x1234.png
    ├── image_nr1_off0x5678.bmp
    ├── image_nr2_off0x9ABC.bin
    └── msi_structure_info.txt
```

지원 확장자:

```text
.bin, .jpg, .jpeg, .png, .bmp, .ico
```

파일명 규칙:

```text
image_nr{번호}_off0x{16진수오프셋}.{확장자}
```

[파일 탐색기에서 `msi_extracted/MSI_pack_1` 폴더, 이미지 파일, `msi_structure_info.txt`가 보이는 장면]

## MSI 리패킹 실행

GUI에서 실행:

1. 제조사를 `MSI`로 선택합니다.
2. `리패킹` 탭을 엽니다.
3. `추출 이미지 디렉터리`에 `msi_extracted` 경로를 지정합니다.
4. 가능하면 `원본 BIOS 파일`도 지정합니다.
5. 필요하면 `출력 파일`을 지정합니다.
6. `리패킹 시작`을 누릅니다.

[MSI 리패킹 완료 후 작업 로그에 구조 보존 모드, 변경 감지 결과, 출력 파일 경로가 보이는 장면]

CLI에서 실행:

```bash
python3 msi_main.py repack /path/to/msi_extracted
```

출력 파일:

```text
<추출디렉터리명>_msi_repacked.bin
<추출디렉터리명>_msi_repacked_repack_report.txt
```

## 리패킹 모드

MSI 리패커는 입력 디렉터리 안에 `MSI_pack`으로 시작하는 하위 폴더가 있는지 확인합니다.

| 조건 | 처리 방식 |
|---|---|
| `MSI_pack*` 폴더 있음 | 구조 보존 모드 |
| `MSI_pack*` 폴더 없음 | 일반 모드: 입력 디렉터리의 이미지 파일을 이름 순서 또는 번호 순서로 리패킹 |
| 원본 BIOS 파일 제공 | 원본 분석 결과를 사용해 변경 감지와 구조 보존을 강화 |
| 원본 BIOS 파일 없음 | 추출 폴더와 메타데이터를 기준으로 리패킹 |

원본 파일을 지정했는데 추출 이미지가 원본과 동일하면 원본 파일을 그대로 복사합니다.

## 드래그 앤 드롭 통합 처리

Windows에서 `.bin` 파일을 `batch\msi_tools.bat` 또는 `msi_main.py` 실행 흐름으로 전달하면 통합 처리가 시도됩니다.

통합 처리 흐름:

1. 원본 MSI 파일 분석
2. 원본 파일이 있는 폴더의 `msi_extracted` 확인
3. `MSI_pack_` 폴더 확인
4. 구조 보존 리패킹
5. 분석 리포트와 리패킹 파일 생성

주의: 이 흐름도 추출 자체를 수행하지 않습니다. `msi_extracted/MSI_pack_*` 폴더가 미리 있어야 합니다.
