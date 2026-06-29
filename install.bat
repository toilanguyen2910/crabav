@echo off
REM CrabAV Windows Installation Script

echo ============================================================
echo CrabAV Installation - Windows
echo ============================================================
echo.

REM Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python not found
    echo Please install Python 3.11+ from python.org
    pause
    exit /b 1
)

echo [1/4] Python detected
echo.

REM Create virtual environment
echo [2/4] Creating virtual environment...
python -m venv venv
if %errorlevel% neq 0 (
    echo Error: Failed to create virtual environment
    pause
    exit /b 1
)
echo.

REM Activate and install
echo [3/4] Installing dependencies...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo Error: Failed to install dependencies
    pause
    exit /b 1
)
echo.

REM Create directories
echo [4/4] Setting up directories...
mkdir data\quarantine 2>nul
mkdir data\backups 2>nul
mkdir logs 2>nul
mkdir data\database 2>nul
echo.

echo ============================================================
echo Installation Complete!
echo ============================================================
echo.
echo Quick Start:
echo   venv\Scripts\activate
echo   python -m src
echo.
echo With UI:
echo   cd ui
echo   npm install
echo   npm run electron-dev
echo.
echo ============================================================
pause
