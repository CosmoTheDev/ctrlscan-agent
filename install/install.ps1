param(
  [string]$Version = "latest",
  [string]$BinDir = "$HOME\.ctrlscan\bin"
)

$ErrorActionPreference = "Stop"

function Write-Info($msg) { Write-Host "[ctrlscan-install] $msg" }

$owner = "CosmoTheDev"
$repo  = "ctrlscan-agent"

function Get-ReleaseTag {
  param([string]$RequestedVersion)
  $api = if ($RequestedVersion -eq "latest") {
    "https://api.github.com/repos/$owner/$repo/releases/latest"
  } else {
    "https://api.github.com/repos/$owner/$repo/releases/tags/$RequestedVersion"
  }
  $release = Invoke-RestMethod -Uri $api
  if (-not $release.tag_name) { throw "Release tag not found" }
  return $release.tag_name
}

function Get-Arch {
  switch ($env:PROCESSOR_ARCHITECTURE.ToLower()) {
    "amd64" { return "x86_64" }
    "arm64" { return "arm64" }
    default { throw "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
  }
}

$tag = Get-ReleaseTag -RequestedVersion $Version
$versionNoV = $tag.TrimStart("v")
$arch = Get-Arch
$asset = "ctrlscan_${versionNoV}_Windows_${arch}.zip"
$url = "https://github.com/$owner/$repo/releases/download/$tag/$asset"

New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ctrlscan-install-" + [Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

try {
  $zip = Join-Path $tmp $asset
  Write-Info "Downloading $asset"
  Invoke-WebRequest -Uri $url -OutFile $zip
  Expand-Archive -Path $zip -DestinationPath $tmp -Force

  $bin = Get-ChildItem -Path $tmp -Recurse -Filter "ctrlscan.exe" | Select-Object -First 1
  if (-not $bin) { throw "ctrlscan.exe not found in release artifact" }

  Copy-Item $bin.FullName (Join-Path $BinDir "ctrlscan.exe") -Force
  Write-Info "Installed to $(Join-Path $BinDir 'ctrlscan.exe')"
  Write-Host ""
  Write-Host "Add to PATH if needed:"
  Write-Host "  $BinDir"
  Write-Host ""
  Write-Host "Then run: ctrlscan onboard"
}
finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
