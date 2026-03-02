# setup.ps1 - Install build dependencies for ctrlscan on Windows
$ErrorActionPreference = "Stop"

Write-Host "Setting up build dependencies..." -ForegroundColor Cyan

# Check if gcc is already available
$gccPath = Get-Command gcc -ErrorAction SilentlyContinue
if ($gccPath) {
    Write-Host "gcc is already installed: $($gccPath.Source)" -ForegroundColor Green
    & gcc --version | Select-Object -First 1
    Write-Host ""
    Write-Host "Setup complete. Run '.\scripts\install.ps1' to build and install ctrlscan." -ForegroundColor Green
    exit 0
}

Write-Host "gcc not found, installing MinGW-w64..." -ForegroundColor Yellow

# Try winget first (built into Windows 11 and Windows 10 1709+)
$winget = Get-Command winget -ErrorAction SilentlyContinue
if ($winget) {
    Write-Host "Using winget to install MinGW-w64..." -ForegroundColor Cyan
    winget install -e --id mingw-w64.mingw-w64 --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "MinGW-w64 installed successfully." -ForegroundColor Green
        Write-Host "IMPORTANT: You may need to restart your terminal or add MinGW to PATH." -ForegroundColor Yellow
        Write-Host "Default install location: C:\mingw64\bin" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Add to PATH by running:" -ForegroundColor Cyan
        Write-Host '  $env:Path += ";C:\mingw64\bin"' -ForegroundColor White
        Write-Host "Or add permanently via System Properties > Environment Variables" -ForegroundColor White
        exit 0
    }
    Write-Host "winget install failed, trying chocolatey..." -ForegroundColor Yellow
}

# Try chocolatey
$choco = Get-Command choco -ErrorAction SilentlyContinue
if ($choco) {
    Write-Host "Using chocolatey to install MinGW..." -ForegroundColor Cyan
    choco install mingw -y
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "MinGW installed successfully." -ForegroundColor Green
        Write-Host "IMPORTANT: Restart your terminal to refresh PATH." -ForegroundColor Yellow
        exit 0
    }
    Write-Host "chocolatey install failed, trying scoop..." -ForegroundColor Yellow
}

# Try scoop
$scoop = Get-Command scoop -ErrorAction SilentlyContinue
if ($scoop) {
    Write-Host "Using scoop to install MinGW..." -ForegroundColor Cyan
    scoop install mingw
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "MinGW installed successfully." -ForegroundColor Green
        Write-Host "IMPORTANT: Restart your terminal to refresh PATH." -ForegroundColor Yellow
        exit 0
    }
}

# No package manager found
Write-Host ""
Write-Host "No supported package manager found (winget, chocolatey, or scoop)." -ForegroundColor Red
Write-Host ""
Write-Host "Please install MinGW-w64 manually:" -ForegroundColor Yellow
Write-Host "  Option 1: Install winget (comes with App Installer from Microsoft Store)" -ForegroundColor White
Write-Host "  Option 2: Install Chocolatey: https://chocolatey.org/install" -ForegroundColor White
Write-Host "  Option 3: Install Scoop: https://scoop.sh" -ForegroundColor White
Write-Host "  Option 4: Download MinGW-w64 directly: https://www.mingw-w64.org/downloads/" -ForegroundColor White
exit 1
