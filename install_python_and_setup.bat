@echo off
@echo Python Installation and Setup Script
@echo ===================================
@echo.
@echo This script will help you install Python and set up the domain scanner application.
@echo.

@echo Checking if Python is already installed...
py --version >nul 2>&1
if %errorlevel% == 0 (
    @echo Python is already installed.
    goto setup_app
) else (
    python --version >nul 2>&1
    if %errorlevel% == 0 (
        @echo Python is already installed.
        goto setup_app
    ) else (
        @echo Python is not installed. Proceeding with installation...
        goto install_python
    )
)

:install_python
@echo.
@echo Downloading Python installer...
@echo Please visit https://www.python.org/downloads/ and download the latest Python 3.x version
@echo Run the installer and make sure to check "Add Python to PATH" during installation
@echo.
@echo Press any key to open the Python download page in your browser...
pause >nul
start https://www.python.org/downloads/
@echo.
@echo After installing Python, please run this script again or run 'run_web_app.bat' directly
@echo.
goto end

:setup_app
@echo Setting up the domain scanner application...
@echo.

@echo Installing required Python packages...
py -m pip install -r requirements.txt
if %errorlevel% == 0 (
    @echo Packages installed successfully.
) else (
    @echo Failed to install packages. Trying with pip3...
    py -m pip3 install -r requirements.txt
)

@echo.
@echo Setup complete!
@echo You can now run the domain scanner application using:
@echo 1. run_web_app.bat - for the web interface
@echo 2. scan_domain.bat - for the command-line interface
@echo.

:end
@echo Press any key to exit...
pause >nul