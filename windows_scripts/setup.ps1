# setup.ps1 - Install build dependencies for ctrlscan on Windows
$ErrorActionPreference = "Stop"

Write-Host "Setting up build dependencies..." -ForegroundColor Cyan
Write-Host ""

$needsRestart = $false

# Helper function to install via available package manager
function Install-Package {
    param([string]$WingetId, [string]$ChocoName, [string]$ScoopName, [string]$DisplayName)

    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        Write-Host "Using winget to install $DisplayName..." -ForegroundColor Cyan
        winget install -e --id $WingetId --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -eq 0) {
            return $true
        }
        Write-Host "winget install failed, trying alternatives..." -ForegroundColor Yellow
    }

    $choco = Get-Command choco -ErrorAction SilentlyContinue
    if ($choco) {
        Write-Host "Using chocolatey to install $DisplayName..." -ForegroundColor Cyan
        choco install $ChocoName -y
        if ($LASTEXITCODE -eq 0) {
            return $true
        }
        Write-Host "chocolatey install failed, trying scoop..." -ForegroundColor Yellow
    }

    $scoop = Get-Command scoop -ErrorAction SilentlyContinue
    if ($scoop) {
        Write-Host "Using scoop to install $DisplayName..." -ForegroundColor Cyan
        scoop install $ScoopName
        if ($LASTEXITCODE -eq 0) {
            return $true
        }
    }

    return $false
}

# === Check and install Go ===
Write-Host "Checking for Go..." -ForegroundColor Cyan
$goPath = Get-Command go -ErrorAction SilentlyContinue
if ($goPath) {
    Write-Host "Go is already installed: $($goPath.Source)" -ForegroundColor Green
    & go version
} else {
    Write-Host "Go not found, installing..." -ForegroundColor Yellow
    $installed = Install-Package -WingetId "GoLang.Go" -ChocoName "golang" -ScoopName "go" -DisplayName "Go"
    if ($installed) {
        Write-Host "Go installed successfully." -ForegroundColor Green
        $needsRestart = $true
    } else {
        Write-Host ""
        Write-Host "Failed to install Go automatically." -ForegroundColor Red
        Write-Host "Please install manually from: https://go.dev/dl/" -ForegroundColor Yellow
        exit 1
    }
}
Write-Host ""

# === Check and install gcc (MinGW-w64) ===
Write-Host "Checking for gcc..." -ForegroundColor Cyan
$gccPath = Get-Command gcc -ErrorAction SilentlyContinue
if ($gccPath) {
    Write-Host "gcc is already installed: $($gccPath.Source)" -ForegroundColor Green
    & gcc --version | Select-Object -First 1
} else {
    Write-Host "gcc not found, installing MinGW-w64..." -ForegroundColor Yellow
    $installed = Install-Package -WingetId "mingw-w64.mingw-w64" -ChocoName "mingw" -ScoopName "mingw" -DisplayName "MinGW-w64"
    if ($installed) {
        Write-Host "MinGW-w64 installed successfully." -ForegroundColor Green
        $needsRestart = $true
    } else {
        Write-Host ""
        Write-Host "Failed to install MinGW-w64 automatically." -ForegroundColor Red
        Write-Host "No supported package manager found (winget, chocolatey, or scoop)." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please install manually:" -ForegroundColor Yellow
        Write-Host "  Option 1: Install winget (comes with App Installer from Microsoft Store)" -ForegroundColor White
        Write-Host "  Option 2: Install Chocolatey: https://chocolatey.org/install" -ForegroundColor White
        Write-Host "  Option 3: Install Scoop: https://scoop.sh" -ForegroundColor White
        Write-Host "  Option 4: Download MinGW-w64 directly: https://www.mingw-w64.org/downloads/" -ForegroundColor White
        exit 1
    }
}
Write-Host ""

# === Done ===
Write-Host "========================================" -ForegroundColor Green
if ($needsRestart) {
    Write-Host "Setup complete!" -ForegroundColor Green
    Write-Host ""
    Write-Host "IMPORTANT: Restart your terminal to refresh PATH," -ForegroundColor Yellow
    Write-Host "then run:" -ForegroundColor Yellow
    Write-Host "  .\windows_scripts\install.ps1" -ForegroundColor White
} else {
    Write-Host "All dependencies are installed!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Run '.\windows_scripts\install.ps1' to build and install ctrlscan." -ForegroundColor Cyan
}
Write-Host "========================================" -ForegroundColor Green
