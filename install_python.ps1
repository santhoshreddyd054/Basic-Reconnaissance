# PowerShell script to download and install Python
Write-Host "Python Installation Script" -ForegroundColor Green
Write-Host "========================" -ForegroundColor Green
Write-Host ""

# Check if Python is already installed
Write-Host "Checking if Python is already installed..." -ForegroundColor Yellow
$pythonExists = Get-Command python -ErrorAction SilentlyContinue
if ($pythonExists) {
    Write-Host "Python is already installed:" -ForegroundColor Green
    python --version
    exit 0
}

Write-Host "Python not found. Proceeding with installation..." -ForegroundColor Yellow

# Get the latest Python download URL
Write-Host "Fetching latest Python download URL..." -ForegroundColor Yellow
try {
    $webClient = New-Object System.Net.WebClient
    $pythonPage = $webClient.DownloadString("https://www.python.org/downloads/windows/")
    
    # Extract the download link for Windows executable
    if ($pythonPage -match 'https://www.python.org/ftp/python/[\d\.]+/python-[\d\.]+-amd64\.exe') {
        $downloadUrl = $matches[0]
        Write-Host "Found download URL: $downloadUrl" -ForegroundColor Green
    } else {
        Write-Host "Could not find download URL. Please download manually from https://www.python.org/downloads/" -ForegroundColor Red
        Start-Process "https://www.python.org/downloads/"
        exit 1
    }
} catch {
    Write-Host "Failed to fetch download URL. Please download manually from https://www.python.org/downloads/" -ForegroundColor Red
    Start-Process "https://www.python.org/downloads/"
    exit 1
}

# Download Python installer
Write-Host "Downloading Python installer..." -ForegroundColor Yellow
$installerPath = "$env:TEMP\python-installer.exe"
try {
    $webClient.DownloadFile($downloadUrl, $installerPath)
    Write-Host "Download completed: $installerPath" -ForegroundColor Green
} catch {
    Write-Host "Failed to download Python installer. Please download manually." -ForegroundColor Red
    Start-Process "https://www.python.org/downloads/"
    exit 1
}

# Install Python with PATH option
Write-Host "Installing Python... (This may take a few minutes)" -ForegroundColor Yellow
Write-Host "Please wait for the installation to complete..." -ForegroundColor Yellow
try {
    Start-Process -FilePath $installerPath -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1", "Include_test=0" -Wait
    Write-Host "Python installation completed successfully!" -ForegroundColor Green
} catch {
    Write-Host "Failed to install Python automatically. Please run the installer manually." -ForegroundColor Red
    Start-Process $installerPath
    exit 1
}

# Verify installation
Write-Host "Verifying Python installation..." -ForegroundColor Yellow
Start-Sleep -Seconds 3
$pythonExists = Get-Command python -ErrorAction SilentlyContinue
if ($pythonExists) {
    Write-Host "Python installation verified:" -ForegroundColor Green
    python --version
    Write-Host "Python has been successfully installed and added to PATH!" -ForegroundColor Green
} else {
    Write-Host "Python installation may require a system restart to update PATH." -ForegroundColor Yellow
    Write-Host "Please restart your computer and try running the application again." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Press any key to exit..."
$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")