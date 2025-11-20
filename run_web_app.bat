@echo off
@echo Domain Scanner Web Application
@echo ============================
@echo.
@echo Checking if Python is installed...
py --version >nul 2>&1
if %errorlevel% neq 0 (
    python --version >nul 2>&1
    if %errorlevel% neq 0 (
        @echo Python is not installed or not in PATH.
        @echo.
        @echo Would you like to install Python now? (Y/N)
        set /p choice=
        if /i "%choice%"=="Y" (
            @echo Running Python installation script...
            powershell -ExecutionPolicy Bypass -File "%~dp0install_python.ps1"
        ) else (
            @echo Please install Python from https://www.python.org/downloads/
            @echo Make sure to check "Add Python to PATH" during installation.
            @echo After installation, run this script again.
            pause
            exit /b
        )
    )
)

@echo.
@echo Installing required packages...
py -m pip install -r requirements.txt
echo.
echo Starting Domain Scanner Web App...
echo The app will be available at http://127.0.0.1:5000 or http://localhost:5000
echo Press Ctrl+C to stop the server.
py simple_app.py
pause