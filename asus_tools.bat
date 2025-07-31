@echo off
chcp 65001 > nul
title ASUS BIOS 이미지 분석/추출/리패킹 도구

echo.
echo ================================================================
echo               ASUS BIOS 이미지 분석/추출/리패킹 도구 v3.0
echo ================================================================
echo.

REM 현재 디렉터리를 bat 파일 위치로 변경
cd /d "%~dp0"

REM Python 설치 확인
python --version > nul 2>&1
if errorlevel 1 (
    echo [오류] Python이 설치되지 않았거나 PATH에 설정되지 않았습니다.
    echo Python 3.6 이상을 설치하고 PATH에 추가해주세요.
    echo.
    echo Python 다운로드: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

echo [OK] Python 확인 완료

REM 필수 Python 파일들 확인
set "missing_files="

if not exist "asus_main.py" (
    set "missing_files=%missing_files% asus_main.py"
)

if not exist "common\file_utils.py" (
    set "missing_files=%missing_files% common\file_utils.py"
)

if not exist "asus\analyzer\asus_analyzer.py" (
    set "missing_files=%missing_files% asus\analyzer\asus_analyzer.py"
)

if not exist "asus\repacker\asus_repacker.py" (
    set "missing_files=%missing_files% asus\repacker\asus_repacker.py"
)

if not "%missing_files%"=="" (
    echo [오류] 다음 필수 파일들을 찾을 수 없습니다:
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
echo   - 분석할 ASUS BIOS 파일을 이 배치 파일로 끌어놓으세요
echo   - 또는 아래 메뉴에서 원하는 기능을 선택하세요
echo.

REM 드래그 앤 드롭으로 파일이 전달된 경우
if "%~1" neq "" (
    echo [DRAG&DROP] 드래그 앤 드롭 모드
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
echo ^|  1. [분석] ASUS BIOS 파일 분석                              ^|
echo ^|     - 파일 구조 분석, 매직 바이트 검사                      ^|
echo ^|     - ASUS Packer 형식 감지                                 ^|
echo ^|     - 분석 보고서 생성 (TXT/MD)                             ^|
echo ^|                                                             ^|
echo ^|  2. [리패킹] ASUS 이미지 리패킹                             ^|
echo ^|     - 수정된 이미지로 재패키징                              ^|
echo ^|     - 원본 구조 최대 보존                                   ^|
echo ^|     - 크기 변화 자동 처리                                   ^|
echo ^|                                                             ^|
echo ^|  3. [종료] 프로그램 종료                                    ^|
echo +-------------------------------------------------------------+
echo.
goto :eof

:get_user_choice
set "target_file=%~1"

set /p choice="선택하세요 (1-5): "

if "%choice%"=="1" (
    echo.
    echo ================================================================
    echo                   [ANALYZE] ASUS BIOS 파일 분석
    echo ================================================================
    call :run_analyzer "%target_file%"
    goto :operation_complete
)

if "%choice%"=="2" (
    echo.
    echo ================================================================
    echo                     [REPACK] ASUS 이미지 리패킹
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
echo [ERROR] 잘못된 선택입니다. 1-4 중에서 선택해주세요.
echo.
goto :get_user_choice "%target_file%"

:run_analyzer
echo.
echo [ANALYZE] ASUS BIOS 파일 분석을 시작합니다...
echo.

if "%~1" neq "" (
    python asus_main.py analyze "%~1"
) else (
    python asus_main.py analyze
)

set exitcode=%errorlevel%
echo.
if %exitcode% equ 0 (
    echo [SUCCESS] ASUS 파일 분석이 성공적으로 완료되었습니다!
) else (
    echo [ERROR] 분석 중 오류가 발생했습니다. (종료 코드: %exitcode%)
)
goto :eof

:run_repacker
echo.
echo [REPACK] ASUS 이미지 리패킹을 시작합니다...
echo.

if "%~1" neq "" (
    python asus_main.py repack "%~1"
) else (
    python asus_main.py repack
)

set exitcode=%errorlevel%
echo.
if %exitcode% equ 0 (
    echo [SUCCESS] ASUS 이미지 리패킹이 성공적으로 완료되었습니다!
) else (
    echo [ERROR] 리패킹 중 오류가 발생했습니다. (종료 코드: %exitcode%)
)
goto :eof

:operation_complete
echo.
echo ================================================================

set /p continue_choice="다른 작업을 수행하시겠습니까? (y/n): "

if /i "%continue_choice%"=="y" (
    echo.
    call :show_menu
    call :get_user_choice "%target_file%"
) else (
    echo.
    echo 작업을 완료했습니다.
    goto :end
)

:end
echo.
echo 이 창을 닫으려면 아무 키나 누르세요...
pause > nul
