@echo off
@echo Domain Scanner CLI Tool
@echo =====================
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
@echo =====================

echo Starting Domain Scanner CLI...
echo Enter 'quit' to exit the application.
py domain_scanner.py
pause