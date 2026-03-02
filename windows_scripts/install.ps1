# install.ps1 - Build and install ctrlscan on Windows
$ErrorActionPreference = "Stop"

$Binary = "ctrlscan.exe"
$InstallDir = "$env:USERPROFILE\.ctrlscan\bin"
$InstallPath = "$InstallDir\$Binary"

Write-Host "Building ctrlscan..." -ForegroundColor Cyan

# Check for gcc
$gccPath = Get-Command gcc -ErrorAction SilentlyContinue
if (-not $gccPath) {
    Write-Host "Error: gcc not found. Run '.\windows_scripts\setup.ps1' first." -ForegroundColor Red
    exit 1
}

# Check for go
$goPath = Get-Command go -ErrorAction SilentlyContinue
if (-not $goPath) {
    Write-Host "Error: Go not found. Run '.\windows_scripts\setup.ps1' first." -ForegroundColor Red
    exit 1
}

# Detect architecture and set environment
$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -eq "AMD64") {
    $env:GOARCH = "amd64"
} elseif ($arch -eq "ARM64") {
    $env:GOARCH = "arm64"
} else {
    Write-Host "Warning: Unknown architecture '$arch', defaulting to amd64" -ForegroundColor Yellow
    $env:GOARCH = "amd64"
}

$env:GOOS = "windows"
$env:CGO_ENABLED = "1"

Write-Host "Building for $env:GOOS/$env:GOARCH..." -ForegroundColor Cyan
go build -o $Binary .
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed." -ForegroundColor Red
    exit 1
}

Write-Host "Build successful." -ForegroundColor Green

# Create install directory
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# Copy binary
Copy-Item $Binary $InstallPath -Force
Write-Host "Installed to $InstallPath" -ForegroundColor Green

# Check if already on PATH
$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($currentPath -like "*$InstallDir*") {
    Write-Host "ctrlscan is already on your PATH." -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "To add ctrlscan to your PATH, run:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  # For this session only:" -ForegroundColor Cyan
    Write-Host "  `$env:Path += `";$InstallDir`"" -ForegroundColor White
    Write-Host ""
    Write-Host "  # To add permanently:" -ForegroundColor Cyan
    Write-Host "  [Environment]::SetEnvironmentVariable('Path', `$env:Path + ';$InstallDir', 'User')" -ForegroundColor White
}

Write-Host ""
Write-Host "Done!" -ForegroundColor Green
