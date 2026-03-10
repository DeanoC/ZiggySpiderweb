param(
    [string]$RepoUrl = "https://github.com/DeanoC/Spiderweb.git",
    [string]$DestDir = "$env:LOCALAPPDATA\Spiderweb\fs-mount-src",
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\Spiderweb\bin"
)

$ErrorActionPreference = "Stop"

function Require-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Missing required command: $Name"
    }
}

function Test-WinFspInstalled {
    if (Test-Path "$env:ProgramFiles(x86)\WinFsp\bin\winfsp-x64.dll") { return $true }
    if (Test-Path "$env:ProgramFiles\WinFsp\bin\winfsp-x64.dll") { return $true }
    return $false
}

Require-Command git
Require-Command zig

if (-not (Test-WinFspInstalled)) {
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) {
        throw "WinFSP is required and was not found. Install WinFSP manually, or install winget and rerun this script."
    }

    Write-Host "Installing WinFSP with winget..."
    winget install --id WinFsp.WinFsp --accept-package-agreements --accept-source-agreements

    if (-not (Test-WinFspInstalled)) {
        throw "WinFSP installation could not be verified. Install WinFSP manually and rerun this script."
    }
}

$destParent = Split-Path -Parent $DestDir
if (-not (Test-Path $destParent)) {
    New-Item -ItemType Directory -Force -Path $destParent | Out-Null
}

if (Test-Path "$DestDir\.git") {
    git -C $DestDir fetch --all --tags
    git -C $DestDir pull --ff-only
    git -C $DestDir submodule update --init --recursive
} else {
    git clone --recurse-submodules $RepoUrl $DestDir
}

Push-Location $DestDir
try {
    zig build fs-mount
} finally {
    Pop-Location
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Force "$DestDir\zig-out\bin\spiderweb-fs-mount.exe" "$InstallDir\spiderweb-fs-mount.exe"

Write-Host "Installed spiderweb-fs-mount.exe to $InstallDir"
Write-Host "Example:"
Write-Host "  spiderweb-fs-mount.exe --namespace-url ws://host:18790/ --project-id proj-a --mount-backend winfsp mount X:"
