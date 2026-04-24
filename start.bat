@echo off
REM =====================================================================
REM  start.bat - Runs certlive right after downloading the project
REM
REM  This script:
REM    1. Checks that Python is installed
REM    2. Creates (if needed) a virtual environment in .venv
REM    3. Installs the dependencies listed in requirements.txt
REM    4. Runs certlive.py, forwarding any arguments
REM
REM  Usage:
REM      start.bat                  (display all domains)
REM      start.bat -k paypal        (filter by keyword)
REM      start.bat -o domains.txt   (save to a file)
REM =====================================================================

setlocal

cd /d "%~dp0"

REM --- 1. Check that Python is available -------------------------------
where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in the PATH.
    echo Download it from https://www.python.org/downloads/ then run this script again.
    pause
    exit /b 1
)

REM --- 2. Create the virtual environment if needed ---------------------
if not exist ".venv\Scripts\python.exe" (
    echo [INFO] Creating the .venv virtual environment ...
    python -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Failed to create the virtual environment.
        pause
        exit /b 1
    )
)

REM --- 3. Install dependencies -----------------------------------------
echo [INFO] Installing dependencies ...
".venv\Scripts\python.exe" -m pip install --upgrade pip >nul
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)

REM --- 4. Run certlive -------------------------------------------------
echo [INFO] Starting certlive ...
echo.
".venv\Scripts\python.exe" certlive.py %*

endlocal
