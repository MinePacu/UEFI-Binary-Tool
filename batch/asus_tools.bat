@echo off
setlocal EnableExtensions
chcp 65001 >nul

set "BATCH_DIR=%~dp0"
for %%I in ("%BATCH_DIR%..") do set "PROJECT_ROOT=%%~fI"
cd /d "%PROJECT_ROOT%"
call "%BATCH_DIR%_lang.bat" ASUS
title %TITLE%

echo.
echo ================================================================
echo               %BANNER_TITLE%
echo ================================================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo %PYTHON_MISSING_1%
    echo %PYTHON_MISSING_2%
    echo.
    echo %PYTHON_DOWNLOAD%
    echo.
    pause
    exit /b 1
)
echo %PYTHON_OK%

set "missing_files="
if not exist "asus_main.py" set "missing_files=%missing_files% asus_main.py"
if not exist "common\file_utils.py" set "missing_files=%missing_files% common\file_utils.py"
if not exist "asus\analyzer\asus_analyzer.py" set "missing_files=%missing_files% asus\analyzer\asus_analyzer.py"
if not exist "asus\repacker\asus_repacker.py" set "missing_files=%missing_files% asus\repacker\asus_repacker.py"

if not "%missing_files%"=="" (
    echo %REQUIRED_MISSING%
    for %%f in (%missing_files%) do echo   - %%f
    echo.
    echo %REQUIRED_HINT%
    echo.
    pause
    exit /b 1
)
echo %REQUIRED_OK%

echo.
echo ================================================================
echo                        %MAIN_MENU%
echo ================================================================
echo.
echo %TIP_USAGE%
echo %TIP_DRAG%
echo %TIP_MENU%
echo.

if "%~1" neq "" (
    echo %DRAG_MODE%
    echo %PASSED_FILE% "%~nx1"
    echo %FILE_PATH% "%~1"
    echo.
    if not exist "%~1" (
        echo %FILE_NOT_FOUND%
        echo %FILE_LABEL% "%~1"
        echo.
        pause
        exit /b 1
    )
    echo %FILE_OK_MENU%
    echo.
    call :show_menu
    call :get_user_choice "%~1"
) else (
    echo %INTERACTIVE_MODE%
    echo.
    call :show_menu
    call :get_user_choice
)

goto :end

:show_menu
echo +-------------------------------------------------------------+
echo ^|                      %MENU_TITLE%
echo +-------------------------------------------------------------+
echo ^|  %MENU1%
echo ^|     %MENU1D1%
echo ^|     %MENU1D2%
echo ^|     %MENU1D3%
echo ^|
echo ^|  %MENU2%
echo ^|     %MENU2D1%
echo ^|     %MENU2D2%
echo ^|     %MENU2D3%
echo ^|
echo ^|  %MENU3%
echo +-------------------------------------------------------------+
echo.
goto :eof

:get_user_choice
set "target_file=%~1"
:choice_loop
set /p choice="%PROMPT_CHOICE%"

if "%choice%"=="1" (
    echo.
    echo ================================================================
    echo                   %ANALYZE_HEADER%
    echo ================================================================
    call :run_analyzer "%target_file%"
    goto :operation_complete
)

if "%choice%"=="2" (
    echo.
    echo ================================================================
    echo                     %REPACK_HEADER%
    echo ================================================================
    call :run_repacker "%target_file%"
    goto :operation_complete
)

if "%choice%"=="3" (
    echo.
    echo %EXITING%
    goto :end
)

echo.
echo %INVALID_CHOICE%
echo.
goto :choice_loop

:run_analyzer
echo.
echo %ANALYZE_START%
echo.
if "%~1" neq "" (
    python asus_main.py analyze "%~1"
) else (
    python asus_main.py analyze
)
set "exitcode=%errorlevel%"
echo.
if "%exitcode%"=="0" (
    echo %ANALYZE_SUCCESS%
) else (
    echo %ERROR_WITH_CODE% %exitcode%
)
goto :eof

:run_repacker
echo.
echo %REPACK_START%
echo.
if "%~1" neq "" (
    python asus_main.py repack "%~1"
) else (
    python asus_main.py repack
)
set "exitcode=%errorlevel%"
echo.
if "%exitcode%"=="0" (
    echo %REPACK_SUCCESS%
) else (
    echo %ERROR_WITH_CODE% %exitcode%
)
goto :eof

:operation_complete
echo.
echo ================================================================
set /p continue_choice="%CONTINUE_PROMPT%"
if /I "%continue_choice%"=="Y" (
    echo.
    call :show_menu
    call :get_user_choice "%target_file%"
) else (
    echo.
    echo %DONE%
    goto :end
)

:end
echo.
echo %CLOSE_PROMPT%
pause >nul
