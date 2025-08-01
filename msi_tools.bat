@echo off
REM MSI BIOS Section Binary 분석/리패킹 도구
REM Windows용 실행 스크립트 (드래그 앤 드롭 지원)

REM Windows 콘솔 한글 인코딩 설정
chcp 65001 >nul 2>&1

REM 콘솔 창 크기 및 버퍼 설정 (한글 표시 개선)
mode con: cols=120 lines=40

title MSI BIOS 분석/리패킹 도구

echo.
echo ================================================================
echo               MSI BIOS Section Binary 분석/리패킹 도구 v1.0
echo ================================================================
echo.

REM 현재 디렉터리를 bat 파일 위치로 변경
cd /d "%~dp0"

REM Python 설치 확인
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python이 설치되어 있지 않거나 PATH에 없습니다.
    echo Python 3.6 이상을 설치해주세요.
    echo.
    echo Python 다운로드: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

echo [OK] Python 확인 완료

REM 필수 Python 파일들 확인
set "missing_files="

if not exist "msi_main.py" (
    set "missing_files=%missing_files% msi_main.py"
)

if not exist "msi\analyzer\msi_analyzer.py" (
    set "missing_files=%missing_files% msi\analyzer\msi_analyzer.py"
)

if not exist "msi\repacker\msi_repacker.py" (
    set "missing_files=%missing_files% msi\repacker\msi_repacker.py"
)

if not "%missing_files%"=="" (
    echo [ERROR] 다음 필수 파일들을 찾을 수 없습니다:
    for %%f in (%missing_files%) do echo   - %%f
    echo.
    echo 모든 필수 파일들이 올바른 위치에 있는지 확인해주세요.
    echo.
    pause
    exit /b 1
)

echo [OK] 모든 필수 파일 확인 완료

echo.
echo ================================================================
echo                        메인 메뉴
echo ================================================================
echo.
echo [TIP] 사용 방법:
echo   - 분석할 MSI BIOS 파일을 이 배치 파일로 끌어놓으세요
echo   - 또는 아래 메뉴에서 원하는 기능을 선택하세요
echo.

REM 드래그 앤 드롭으로 파일이 전달된 경우
if "%~1" neq "" (
    echo [DRAG^&DROP] 드래그 앤 드롭 모드
    echo 전달된 파일: "%~nx1"
    echo 파일 경로: "%~1"
    echo.
    
    REM 파일 존재 확인
    if not exist "%~1" (
        echo [ERROR] 전달된 파일을 찾을 수 없습니다.
        echo 파일: "%~1"
        echo.
        pause
        exit /b 1
    )
    
    echo [OK] 파일 확인 완료. 메뉴를 선택하세요...
    echo.
    
    REM 드래그 앤 드롭 모드에서도 메뉴 표시
    call :show_menu
    call :get_user_choice "%~1"
) else (
    REM 일반 대화형 모드
    echo [INTERACTIVE] 대화형 모드
    echo.
    call :show_menu
    call :get_user_choice
)

goto :end

:show_menu
echo +-------------------------------------------------------------+
echo ^|                      기능 선택 메뉴                          ^|
echo +-------------------------------------------------------------+
echo ^|  1. [분석] MSI BIOS 파일 분석                               ^|
echo ^|     - MSI Packer 구조 분석                                  ^|
echo ^|     - 이미지 타입 및 매직 바이트 검사                       ^|
echo ^|     - 분석 보고서 생성                                      ^|
echo ^|                                                             ^|
echo ^|  2. [리패킹] MSI 이미지 리패킹                              ^|
echo ^|     - 추출된 이미지로 재패키징                              ^|
echo ^|     - 원본 구조 보존                                        ^|
echo ^|     - msi_extracted 폴더 필요                               ^|
echo ^|                                                             ^|
echo ^|  3. [종료] 프로그램 종료                                    ^|
echo +-------------------------------------------------------------+
echo.
goto :eof

:get_user_choice
set "target_file=%~1"

set /p choice="선택하세요 (1-3): "

if "%choice%"=="1" (
    echo.
    echo ================================================================
    echo                   [ANALYZE] MSI BIOS 파일 분석
    echo ================================================================
    call :run_analyzer "%target_file%"
    goto :operation_complete
)

if "%choice%"=="2" (
    echo.
    echo ================================================================
    echo                     [REPACK] MSI 이미지 리패킹
    echo ================================================================
    call :run_repacker "%target_file%"
    goto :operation_complete
)

if "%choice%"=="3" (
    echo.
    echo 프로그램을 종료합니다.
    goto :end
)

echo.
echo [ERROR] 잘못된 선택입니다. 1-3 중에서 선택해주세요.
echo.
pause
goto :get_user_choice

:run_analyzer
set "input_file=%~1"

if "%input_file%"=="" (
    echo MSI BIOS 파일 분석 모드입니다.
    echo.
    REM Python UTF-8 출력 강제 설정
    set PYTHONIOENCODING=utf-8
    python msi_main.py analyze
) else (
    echo 파일: "%input_file%"
    echo.
    set PYTHONIOENCODING=utf-8
    python msi_main.py analyze "%input_file%"
)
goto :eof

:run_repacker
set "input_file=%~1"

REM 현재 작업 디렉터리의 msi_extracted 폴더 확인
set "extract_dir=%~dp0msi_extracted"

if not exist "%extract_dir%" (
    echo [ERROR] 추출된 이미지 폴더를 찾을 수 없습니다: "%extract_dir%"
    echo.
    echo 먼저 이미지를 추출하거나, 올바른 msi_extracted 폴더가 있는지 확인하세요.
    echo 현재 디렉터리: "%~dp0"
    echo.
    pause
    goto :eof
)

echo MSI 이미지 리패킹 모드입니다.
echo 리패킹 대상: "%extract_dir%"
echo.

REM Python UTF-8 출력 강제 설정
set PYTHONIOENCODING=utf-8
python msi_main.py repack "%extract_dir%"
goto :eof

:operation_complete
echo.
echo ================================================================
echo                        작업 완료
echo ================================================================
echo.
echo 생성된 파일들을 확인하세요:
echo - *_msi_analysis_report.txt : 분석 리포트
echo - *_msi_repacked.bin : 리패킹된 BIOS 파일 (리패킹 시)
echo - msi_extracted/ : 추출된 이미지들 (추출 시)
echo.
echo 추가 작업을 하시겠습니까?
set /p continue_choice="계속하려면 Y, 종료하려면 N을 입력하세요: "

if /I "%continue_choice%"=="Y" (
    echo.
    call :show_menu
    call :get_user_choice "%target_file%"
) else (
    goto :end
)

:end
echo.
echo 프로그램을 종료합니다.
pause
exit /b 0
