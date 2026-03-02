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

# Detect architecture
$arch = $env:PROCESSOR_ARCHITECTURE
Write-Host "Detected architecture: $arch" -ForegroundColor Cyan

$gccPath = Get-Command gcc -ErrorAction SilentlyContinue
if ($gccPath) {
    Write-Host "gcc is already installed: $($gccPath.Source)" -ForegroundColor Green
    & gcc --version | Select-Object -First 1

    # Verify gcc matches system architecture
    $gccArch = & gcc -dumpmachine 2>$null
    if ($arch -eq "ARM64" -and $gccArch -notlike "*aarch64*" -and $gccArch -notlike "*arm64*") {
        Write-Host ""
        Write-Host "WARNING: You have ARM64 Windows but x86_64 gcc installed." -ForegroundColor Yellow
        Write-Host "This may cause build failures. Consider installing ARM64 MinGW:" -ForegroundColor Yellow
        Write-Host "  https://github.com/mstorsjo/llvm-mingw/releases" -ForegroundColor White
        Write-Host "  (Download: llvm-mingw-<version>-ucrt-aarch64.zip)" -ForegroundColor White
    } elseif ($arch -eq "AMD64" -and $gccArch -like "*aarch64*") {
        Write-Host ""
        Write-Host "WARNING: You have AMD64 Windows but ARM64 gcc installed." -ForegroundColor Yellow
        Write-Host "This will cause build failures. Please reinstall MinGW for x86_64." -ForegroundColor Yellow
    }
} else {
    Write-Host "gcc not found, installing MinGW-w64..." -ForegroundColor Yellow

    if ($arch -eq "ARM64") {
        Write-Host ""
        Write-Host "ARM64 Windows detected. Installing llvm-mingw (ARM64-native)..." -ForegroundColor Yellow

        $llvmInstallDir = "C:\llvm-mingw"
        $llvmBinDir = "$llvmInstallDir\bin"

        # Check if already installed manually
        if (Test-Path "$llvmBinDir\gcc.exe") {
            Write-Host "llvm-mingw already installed at $llvmInstallDir" -ForegroundColor Green
            # Add to PATH for current session
            if ($env:Path -notlike "*$llvmBinDir*") {
                $env:Path = "$llvmBinDir;$env:Path"
            }
        } else {
            # Download and install llvm-mingw from GitHub
            Write-Host "Downloading llvm-mingw from GitHub..." -ForegroundColor Cyan

            try {
                # Get latest release info
                $releaseUrl = "https://api.github.com/repos/mstorsjo/llvm-mingw/releases/latest"
                $release = Invoke-RestMethod -Uri $releaseUrl -Headers @{"User-Agent"="PowerShell"}

                # Find the ARM64 UCRT asset
                $asset = $release.assets | Where-Object { $_.name -like "*ucrt-aarch64.zip" } | Select-Object -First 1

                if (-not $asset) {
                    throw "Could not find ARM64 asset in latest release"
                }

                $downloadUrl = $asset.browser_download_url
                $zipFile = "$env:TEMP\llvm-mingw-arm64.zip"
                $extractDir = "$env:TEMP\llvm-mingw-extract"

                Write-Host "Downloading: $($asset.name)" -ForegroundColor Cyan
                Invoke-WebRequest -Uri $downloadUrl -OutFile $zipFile -UseBasicParsing

                Write-Host "Extracting..." -ForegroundColor Cyan
                if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
                Expand-Archive -Path $zipFile -DestinationPath $extractDir -Force

                # Find the extracted folder (it has a version number in the name)
                $extractedFolder = Get-ChildItem $extractDir | Select-Object -First 1

                # Move to final location
                if (Test-Path $llvmInstallDir) { Remove-Item $llvmInstallDir -Recurse -Force }
                Move-Item $extractedFolder.FullName $llvmInstallDir

                # Cleanup
                Remove-Item $zipFile -Force
                Remove-Item $extractDir -Recurse -Force

                Write-Host "llvm-mingw installed to $llvmInstallDir" -ForegroundColor Green

                # Add to PATH permanently
                $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
                if ($currentPath -notlike "*$llvmBinDir*") {
                    [Environment]::SetEnvironmentVariable("Path", "$llvmBinDir;$currentPath", "User")
                    Write-Host "Added $llvmBinDir to user PATH" -ForegroundColor Green
                }

                # Add to current session
                $env:Path = "$llvmBinDir;$env:Path"
                $needsRestart = $true

            } catch {
                Write-Host ""
                Write-Host "Automatic download failed: $_" -ForegroundColor Red
                Write-Host ""
                Write-Host "Please install llvm-mingw manually:" -ForegroundColor Yellow
                Write-Host "  1. Download from: https://github.com/mstorsjo/llvm-mingw/releases" -ForegroundColor White
                Write-Host "     (Get: llvm-mingw-<version>-ucrt-aarch64.zip)" -ForegroundColor White
                Write-Host "  2. Extract to C:\llvm-mingw" -ForegroundColor White
                Write-Host "  3. Add to PATH:" -ForegroundColor White
                Write-Host '     [Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\llvm-mingw\bin", "User")' -ForegroundColor White
                Write-Host "  4. Restart terminal" -ForegroundColor White
                exit 1
            }
        }

        # Verify installation
        $gccCheck = Get-Command gcc -ErrorAction SilentlyContinue
        if (-not $gccCheck) {
            Write-Host ""
            Write-Host "gcc still not found. You may need to restart your terminal." -ForegroundColor Yellow
            $needsRestart = $true
        }
    } else {
        # AMD64 - use standard MinGW
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
