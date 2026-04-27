# ASUS 분석 및 리패킹

## 지원 범위

ASUS 워크플로는 ASUS Packer 구조가 포함된 BIOS/UEFI Section Binary를 대상으로 합니다. 프로그램은 파일 안에서 ASUS Packer 패키지 패턴을 찾고, 패키지 안의 이미지 메타데이터와 이미지 데이터를 기준으로 분석 또는 리패킹합니다.

## ASUS 파일 분석

GUI에서 실행:

1. 제조사를 `ASUS`로 선택합니다.
2. `분석` 탭을 엽니다.
3. 분석할 BIOS/Section 파일을 선택합니다.
4. `분석 시작`을 누릅니다.

[ASUS 분석 실행 후 작업 로그에 `ASUS Packer 패키지 수`와 분석 진행 로그가 표시된 장면]

CLI에서 실행:

```bash
python3 asus_main.py analyze /path/to/asus_section.bin
```

분석 과정에서 확인하는 항목:

- ASUS Packer 패키지 구조 검증
- 매직 바이트 분석
- UEFI, BIOS, ASUS, Intel, AMD 등 문자열/패턴 검색
- PNG, JPEG, BMP 등 임베디드 이미지 후보 탐지
- 엔트로피 분석
- NULL 바이트 시퀀스와 정렬 구조 확인
- 분석 요약 생성

생성 파일:

```text
<원본파일명>_analysis.txt
<원본파일명>_analysis.md
```

## ASUS 리패킹 준비

ASUS 리패킹에는 다음 두 가지가 필요합니다.

1. 원본 ASUS BIOS/Section 바이너리
2. 추출 및 수정된 이미지 파일이 들어 있는 디렉터리

현재 리패커가 기대하는 폴더 구조:

```text
asus_extracted/
└── asus_pack_1/
    ├── image_nr1_off0x00001234.png
    ├── image_nr2_off0x00005678.bmp
    └── ...
```

이미지 파일명은 원본 이미지 번호와 오프셋을 기준으로 매핑됩니다.

```text
image_nr{번호}_off0x{8자리16진수}.{확장자}
```

예:

```text
image_nr1_off0x0000a240.png
```

파일명 규칙이 깨지면 해당 이미지는 리패킹 대상에서 제외될 수 있습니다.

[파일 탐색기에서 `asus_extracted/asus_pack_1` 폴더와 `image_nr..._off0x...` 이미지 파일들이 보이는 장면]

## ASUS 리패킹 실행

GUI에서 실행:

1. 제조사를 `ASUS`로 선택합니다.
2. `리패킹` 탭을 엽니다.
3. `원본 BIOS 파일`에 원본 ASUS Section Binary를 지정합니다.
4. `추출 이미지 디렉터리`에 `asus_extracted` 경로를 지정합니다.
5. 필요하면 `출력 파일`을 지정합니다.
6. `리패킹 시작`을 누릅니다.

[ASUS 리패킹 완료 후 작업 로그에 변경 요약, 출력 파일 경로, 완료 메시지가 보이는 장면]

CLI에서 실행:

```bash
python3 asus_main.py repack /path/to/original_asus_section.bin
```

CLI 모드는 실행 중 추출 디렉터리와 출력 파일명을 입력받습니다.

## 리패킹 동작 방식

ASUS 리패커는 원본 파일에서 ASUS Packer 패키지와 이미지 메타데이터를 먼저 읽습니다. 이후 추출 폴더의 이미지와 원본 이미지 데이터를 비교하여 실제로 바뀐 이미지만 교체합니다.

동작 방식은 크기 변화에 따라 달라집니다.

| 조건 | 처리 방식 |
|---|---|
| 수정 이미지들의 전체 크기 변화가 0 byte | 원본 오프셋에 이미지 바이트만 직접 교체 |
| 크기 변화가 있음 | 패키지 헤더, 특수 패턴, 이미지 순서, 4바이트 정렬을 보존하며 재구성 |
| 수정된 이미지가 없음 | 원본 파일을 그대로 복사 |

이미지 확장자 또는 컨테이너 형식이 원본과 달라지면 해당 이미지는 건너뜁니다. 예를 들어 원본이 `png`인데 수정 파일이 `jpg`로 바뀌면 교체하지 않습니다.

## 권장 작업 순서

1. 원본 파일을 백업합니다.
2. ASUS Packer 구조로 이미지를 추출합니다.
3. 이미지 파일명과 확장자는 유지한 채 이미지만 수정합니다.
4. GUI 또는 CLI에서 ASUS 리패킹을 실행합니다.
5. 생성된 `_asus_repacked.bin` 파일을 별도 도구로 검증합니다.
