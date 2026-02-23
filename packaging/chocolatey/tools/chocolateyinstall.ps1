$ErrorActionPreference = 'Stop'

$packageName = 'ctrlscan'
$toolsDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$version = '{{VERSION}}'
$checksum = '{{SHA256_WINDOWS_AMD64_ZIP}}'

$url64 = "https://github.com/CosmoTheDev/ctrlscan-agent/releases/download/v$version/ctrlscan_${version}_Windows_x86_64.zip"

$packageArgs = @{
  packageName   = $packageName
  unzipLocation = $toolsDir
  url64bit      = $url64
  checksum64    = $checksum
  checksumType64= 'sha256'
}

Install-ChocolateyZipPackage @packageArgs

$exe = Join-Path $toolsDir 'ctrlscan.exe'
if (-not (Test-Path $exe)) {
  $nested = Get-ChildItem -Path $toolsDir -Recurse -Filter 'ctrlscan.exe' | Select-Object -First 1
  if ($nested) {
    Copy-Item $nested.FullName $exe -Force
  }
}

Write-Host "ctrlscan installed. Run: ctrlscan onboard"
