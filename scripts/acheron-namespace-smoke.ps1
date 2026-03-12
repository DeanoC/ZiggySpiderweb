$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

$SpiderwebUrl = if ($env:SPIDERWEB_URL) { $env:SPIDERWEB_URL } else { "ws://127.0.0.1:18790/" }
$SpiderwebWorkspaceId = $env:SPIDERWEB_WORKSPACE_ID
$SpiderwebWorkspaceToken = $env:SPIDERWEB_WORKSPACE_TOKEN
$SpiderwebAuthToken = $env:SPIDERWEB_AUTH_TOKEN
$SpiderwebAuthTokenFile = if ($env:SPIDERWEB_AUTH_TOKEN_FILE) { $env:SPIDERWEB_AUTH_TOKEN_FILE } else { Join-Path $HOME ".local\share\ziggy-spiderweb\.spiderweb-ltm\auth_tokens.json" }
$SpiderwebAgentId = $env:SPIDERWEB_AGENT_ID
$SpiderwebSessionKey = $env:SPIDERWEB_SESSION_KEY
$SpiderwebMountBackend = if ($env:SPIDERWEB_MOUNT_BACKEND) { $env:SPIDERWEB_MOUNT_BACKEND } else { "auto" }
$SpiderwebFsMountBin = $env:SPIDERWEB_FS_MOUNT_BIN
$SmokeTimeoutSec = if ($env:SMOKE_TIMEOUT_SEC) { [int]$env:SMOKE_TIMEOUT_SEC } else { 20 }
$SmokeConnectRetries = if ($env:SMOKE_CONNECT_RETRIES) { [int]$env:SMOKE_CONNECT_RETRIES } else { 8 }
$SmokeRetryDelayMs = if ($env:SMOKE_RETRY_DELAY_MS) { [int]$env:SMOKE_RETRY_DELAY_MS } else { 500 }
$SmokeRequireRoutedFs = if ($env:SMOKE_REQUIRE_ROUTED_FS) { $env:SMOKE_REQUIRE_ROUTED_FS -ne "0" } else { $true }
$SmokeWritePath = $env:SMOKE_WRITE_PATH
$SmokeWriteRelativePath = if ($env:SMOKE_WRITE_RELATIVE_PATH) { $env:SMOKE_WRITE_RELATIVE_PATH } else { ".spiderweb-fs-mount-smoke.txt" }
$SmokeWriteContent = if ($env:SMOKE_WRITE_CONTENT) { $env:SMOKE_WRITE_CONTENT } else { "spiderweb-fs-mount-smoke-$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())" }
$SmokeProtocolPath = if ($env:SMOKE_PROTOCOL_PATH) { $env:SMOKE_PROTOCOL_PATH } else { "/meta/protocol.json" }
$SmokeUnsupportedTarget = if ($env:SMOKE_UNSUPPORTED_TARGET) { $env:SMOKE_UNSUPPORTED_TARGET } else { "/projects/__spiderweb_fs_mount_smoke__" }
$SmokeUseOsMount = if ($env:SMOKE_USE_OS_MOUNT) { $env:SMOKE_USE_OS_MOUNT -eq "1" } else { $false }
$SmokeMountpoint = $env:SMOKE_MOUNTPOINT
$OnWindows = $env:OS -eq "Windows_NT"

function Resolve-Binary {
    param([string]$Name)

    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    $cacheCandidate = Get-ChildItem (Join-Path $script:RepoRoot ".zig-cache") -Recurse -Filter "$Name.exe" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1 -ExpandProperty FullName
    if ($cacheCandidate) {
        return $cacheCandidate
    }

    $candidates = @(
        (Join-Path $script:RepoRoot "zig-out\bin\$Name"),
        (Join-Path $script:RepoRoot "zig-out\bin\$Name.exe")
    )
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    throw "required binary not found: $Name"
}

function Require-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "required binary not found: $Name"
    }
}

function Invoke-FsMountRaw {
    param([string[]]$FsArgs)

    Push-Location $script:RepoRoot
    try {
        $stdoutPath = Join-Path ([System.IO.Path]::GetTempPath()) ("spiderweb-fs-mount-stdout-" + [guid]::NewGuid().ToString("N") + ".log")
        $stderrPath = Join-Path ([System.IO.Path]::GetTempPath()) ("spiderweb-fs-mount-stderr-" + [guid]::NewGuid().ToString("N") + ".log")
        try {
            $proc = Start-Process -FilePath $script:FsMountBin `
                -ArgumentList ($script:CommonArgs + $FsArgs) `
                -NoNewWindow `
                -PassThru `
                -Wait `
                -RedirectStandardOutput $stdoutPath `
                -RedirectStandardError $stderrPath
            $stdoutText = if (Test-Path $stdoutPath) { Get-Content -LiteralPath $stdoutPath -Raw } else { "" }
            $stderrText = if (Test-Path $stderrPath) { Get-Content -LiteralPath $stderrPath -Raw } else { "" }
            $combinedParts = @($stdoutText, $stderrText) |
                Where-Object { $_ -and $_.Length -gt 0 } |
                ForEach-Object { $_.TrimEnd() }
            $combined = ($combinedParts -join [Environment]::NewLine)
        } finally {
            if (Test-Path $stdoutPath) {
                Remove-Item -LiteralPath $stdoutPath -Force -ErrorAction SilentlyContinue
            }
            if (Test-Path $stderrPath) {
                Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue
            }
        }
        [pscustomobject]@{
            Output = $combined.Trim()
            ExitCode = $proc.ExitCode
        }
    } finally {
        Pop-Location
    }
}

function Invoke-FsMount {
    param([string[]]$FsArgs)

    $result = Invoke-FsMountRaw -FsArgs $FsArgs
    if ($result.ExitCode -ne 0) {
        throw "spiderweb-fs-mount failed for '$($FsArgs -join ' ')': $($result.Output)"
    }
    return $result.Output
}

function Get-FreeDriveMountpoint {
    $usedLetters = Get-PSDrive -PSProvider FileSystem | ForEach-Object { $_.Name.ToUpperInvariant() }
    foreach ($letter in [char[]]([string]"ZYXWVUTSRQPONMLKJIHGFED")) {
        $candidate = [string]$letter
        if ($usedLetters -contains $candidate) {
            continue
        }
        return "${candidate}:"
    }
    throw "no free drive letters are available for WinFSP mount smoke"
}

function Join-MountPath {
    param(
        [string]$MountRoot,
        [string]$RelativePath
    )

    $trimmed = $RelativePath.TrimStart("/", "\").Replace("/", "\")
    if ($MountRoot -match '^[A-Za-z]:\\?$') {
        $root = $MountRoot.TrimEnd("\")
        if ([string]::IsNullOrEmpty($trimmed)) {
            return "$root\"
        }
        return "$root\$trimmed"
    }
    return Join-Path $MountRoot $trimmed
}

function Test-PathSafe {
    param([string]$LiteralPath)

    try {
        return Test-Path -LiteralPath $LiteralPath -ErrorAction Stop
    } catch [System.UnauthorizedAccessException] {
        return $false
    } catch {
        return $false
    }
}

$FsMountBin = if ($SpiderwebFsMountBin) { $SpiderwebFsMountBin } else { Resolve-Binary "spiderweb-fs-mount" }
Require-Command "ConvertFrom-Json"

if (-not $SpiderwebAuthToken -and (Test-Path $SpiderwebAuthTokenFile)) {
    $tokenJson = Get-Content -LiteralPath $SpiderwebAuthTokenFile -Raw | ConvertFrom-Json
    if ($tokenJson.PSObject.Properties.Name -contains "admin_token" -and $tokenJson.admin_token) {
        $SpiderwebAuthToken = [string]$tokenJson.admin_token
    } elseif ($tokenJson.PSObject.Properties.Name -contains "user_token" -and $tokenJson.user_token) {
        $SpiderwebAuthToken = [string]$tokenJson.user_token
    }
}

$CommonArgs = @("--namespace-url", $SpiderwebUrl, "--mount-backend", $SpiderwebMountBackend)
if ($SpiderwebWorkspaceId) { $CommonArgs += @("--workspace-id", $SpiderwebWorkspaceId) }
if ($SpiderwebWorkspaceToken) { $CommonArgs += @("--workspace-token", $SpiderwebWorkspaceToken) }
if ($SpiderwebAuthToken) { $CommonArgs += @("--auth-token", $SpiderwebAuthToken) }
if ($SpiderwebAgentId) { $CommonArgs += @("--agent-id", $SpiderwebAgentId) }
if ($SpiderwebSessionKey) { $CommonArgs += @("--session-key", $SpiderwebSessionKey) }

$statusText = $null
for ($attempt = 1; $attempt -le $SmokeConnectRetries; $attempt += 1) {
    $statusResult = Invoke-FsMountRaw -FsArgs @("status", "--no-probe")
    if ($statusResult.ExitCode -eq 0) {
        try {
            $candidate = $statusResult.Output | ConvertFrom-Json
            if ($candidate.mode -eq "namespace") {
                $statusText = $statusResult.Output
                break
            }
        } catch {
        }
    }
    if ($attempt -eq $SmokeConnectRetries) {
        throw "namespace status probe failed: $($statusResult.Output)"
    }
    Start-Sleep -Milliseconds $SmokeRetryDelayMs
}

$status = $statusText | ConvertFrom-Json
Write-Host "namespace workspace: $($status.project_id)"
Write-Host "namespace agent: $($status.agent_id)"

foreach ($path in @("/agents", "/nodes", "/global")) {
    Write-Host "checking namespace path: $path"
    [void](Invoke-FsMount -FsArgs @("getattr", $path))
}

$protocolText = Invoke-FsMount -FsArgs @("cat", $SmokeProtocolPath)
[void]($protocolText | ConvertFrom-Json)
Write-Host "protocol file read ok: $SmokeProtocolPath"

$resolvedWritePath = $SmokeWritePath
if (-not $resolvedWritePath) {
    $routedEndpoint = $null
    $hasRouter = $status.PSObject.Properties.Name -contains "router"
    if ($hasRouter -and $status.router -and ($status.router.PSObject.Properties.Name -contains "endpoints")) {
        $routedEndpoint = $status.router.endpoints |
            Where-Object {
                $_.export_ro -ne $true -and ($_.source_kind -eq "fs" -or $_.mount_path -like "/nodes/*")
            } |
            Select-Object -First 1
    }
    if ($routedEndpoint) {
        $resolvedWritePath = (($routedEndpoint.mount_path.TrimEnd("/")) + "/" + $SmokeWriteRelativePath)
    }
}

if ($resolvedWritePath) {
    Write-Host "writing routed file: $resolvedWritePath"
    [void](Invoke-FsMount -FsArgs @("write", $resolvedWritePath, $SmokeWriteContent))
    $readBack = Invoke-FsMount -FsArgs @("cat", $resolvedWritePath)
    if ($readBack -ne $SmokeWriteContent) {
        throw "routed write verification failed for $resolvedWritePath"
    }
} elseif ($SmokeRequireRoutedFs) {
    throw "no writable routed filesystem export was discovered"
} else {
    Write-Host "routed fs write skipped: no writable routed export discovered"
}

$unsupportedResult = Invoke-FsMountRaw -FsArgs @("mkdir", $SmokeUnsupportedTarget)
if ($unsupportedResult.ExitCode -eq 0) {
    throw "synthetic namespace mkdir unexpectedly succeeded: $SmokeUnsupportedTarget"
}
Write-Host "synthetic mutation failed as expected: $SmokeUnsupportedTarget"

$mountProc = $null
$mountpoint = $null
$createdMountpoint = $false
$mountStdoutLog = $null
$mountStderrLog = $null

try {
    if ($SmokeUseOsMount) {
        if ($SmokeMountpoint) {
            $mountpoint = $SmokeMountpoint
            if ((-not $OnWindows) -and (-not (Test-Path $mountpoint))) {
                [void](New-Item -ItemType Directory -Path $mountpoint)
            }
        } elseif ($OnWindows) {
            $mountpoint = Join-Path ([System.IO.Path]::GetTempPath()) ("spiderweb-fs-mount-smoke-" + [guid]::NewGuid().ToString("N"))
            $createdMountpoint = $true
        } else {
            $mountpoint = Join-Path ([System.IO.Path]::GetTempPath()) ("spiderweb-fs-mount-smoke-" + [guid]::NewGuid().ToString("N"))
            [void](New-Item -ItemType Directory -Path $mountpoint)
            $createdMountpoint = $true
        }

        $mountStdoutLog = Join-Path ([System.IO.Path]::GetTempPath()) ("spiderweb-fs-mount-smoke-out-" + [guid]::NewGuid().ToString("N") + ".log")
        $mountStderrLog = Join-Path ([System.IO.Path]::GetTempPath()) ("spiderweb-fs-mount-smoke-err-" + [guid]::NewGuid().ToString("N") + ".log")
        $mountArgs = @($CommonArgs + @("mount", $mountpoint))
        $mountProc = Start-Process -FilePath $FsMountBin -ArgumentList $mountArgs -NoNewWindow -PassThru -RedirectStandardOutput $mountStdoutLog -RedirectStandardError $mountStderrLog

        $agentsPath = Join-MountPath $mountpoint "agents"
        $nodesPath = Join-MountPath $mountpoint "nodes"
        $globalPath = Join-MountPath $mountpoint "global"
        $mountedProtocolPath = Join-MountPath $mountpoint $SmokeProtocolPath

        $mountedReady = $false
        for ($attempt = 1; $attempt -le $SmokeConnectRetries; $attempt += 1) {
            if ((Test-PathSafe $agentsPath) -and (Test-PathSafe $nodesPath) -and (Test-PathSafe $globalPath)) {
                $mountedReady = $true
                break
            }
            if ($mountProc.HasExited) {
                $mountOutput = @()
                if ($mountStdoutLog -and (Test-Path $mountStdoutLog)) { $mountOutput += (Get-Content -LiteralPath $mountStdoutLog -Raw) }
                if ($mountStderrLog -and (Test-Path $mountStderrLog)) { $mountOutput += (Get-Content -LiteralPath $mountStderrLog -Raw) }
                throw "mount process exited before the mount became available: $(($mountOutput | Where-Object { $_ } | ForEach-Object { $_.TrimEnd() }) -join [Environment]::NewLine)"
            }
            Start-Sleep -Milliseconds $SmokeRetryDelayMs
        }
        if (-not $mountedReady) {
            $mountOutput = @()
            if ($mountStdoutLog -and (Test-Path $mountStdoutLog)) { $mountOutput += (Get-Content -LiteralPath $mountStdoutLog -Raw) }
            if ($mountStderrLog -and (Test-Path $mountStderrLog)) { $mountOutput += (Get-Content -LiteralPath $mountStderrLog -Raw) }
            $mountOutputText = ($mountOutput | Where-Object { $_ } | ForEach-Object { $_.TrimEnd() }) -join [Environment]::NewLine
            if ($mountOutputText) {
                throw "mountpoint did not become readable: $mountpoint`n$mountOutputText"
            }
            throw "mountpoint did not become readable: $mountpoint"
        }

        [void](Get-Content -LiteralPath $mountedProtocolPath -Raw | ConvertFrom-Json)
        if ($resolvedWritePath) {
            $mountedWritePath = Join-MountPath $mountpoint $resolvedWritePath
            Set-Content -LiteralPath $mountedWritePath -Value $SmokeWriteContent -NoNewline
            $mountedReadBack = Get-Content -LiteralPath $mountedWritePath -Raw
            if ($mountedReadBack -ne $SmokeWriteContent) {
                throw "mounted routed write verification failed for $mountedWritePath"
            }
        }

        Write-Host "mounted namespace check passed: $mountpoint"
    }
} finally {
    if ($mountProc -and -not $mountProc.HasExited) {
        try {
            Stop-Process -Id $mountProc.Id -Force
        } catch {
        }
    }
    if ($mountStdoutLog -and (Test-Path $mountStdoutLog)) {
        Remove-Item -LiteralPath $mountStdoutLog -Force -ErrorAction SilentlyContinue
    }
    if ($mountStderrLog -and (Test-Path $mountStderrLog)) {
        Remove-Item -LiteralPath $mountStderrLog -Force -ErrorAction SilentlyContinue
    }
    if ($createdMountpoint -and $mountpoint -and (Test-Path $mountpoint)) {
        Remove-Item -LiteralPath $mountpoint -Force -Recurse -ErrorAction SilentlyContinue
    }
}

Write-Host "namespace smoke check passed"
