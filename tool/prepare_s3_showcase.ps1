[CmdletBinding()]
param(
    [switch]$ResetArchiveMemory,
    [string]$Confirmation = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Stop-Blocked {
    param([Parameter(Mandatory = $true)][string]$Code)
    throw "BLOCKED:$Code"
}

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$hubRoot = Join-Path $repoRoot 'services\steward_hub'
$python = Join-Path $hubRoot '.venv\Scripts\python.exe'
$database = Join-Path $env:LOCALAPPDATA 'DataSteward\hub\steward.sqlite3'
$admin = Join-Path $hubRoot 'tool\reset_archive_memory_demo.py'
$providerEvidence = Join-Path $repoRoot 'docs\evidence\P0-S3-B\volcengine-live-provider-gate.json'
$exe = Join-Path $repoRoot 'apps\steward_app\build\windows\x64\runner\Debug\steward_app.exe'
$apk = Join-Path $repoRoot 'apps\steward_app\build\app\outputs\flutter-apk\app-debug.apk'

foreach ($required in @($python, $database, $admin, $providerEvidence)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        Stop-Blocked 'required_showcase_input_missing'
    }
}

if ($ResetArchiveMemory) {
    if ($Confirmation -cne 'RESET_S3_ARCHIVE_MEMORY') {
        Stop-Blocked 'exact_reset_confirmation_required'
    }
    if (@(Get-Process steward_app -ErrorAction SilentlyContinue).Count -ne 0) {
        Stop-Blocked 'steward_app_must_be_stopped'
    }
    $listeners = @(Get-NetTCPConnection -LocalPort 9443 -State Listen -ErrorAction SilentlyContinue)
    if ($listeners.Count -ne 0) {
        Stop-Blocked 'showcase_hub_listener_must_be_stopped'
    }
}

$previousPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = Join-Path $hubRoot 'src'
    $arguments = @($admin, '--database', $database)
    if ($ResetArchiveMemory) {
        $arguments += @('--reset', '--confirm', $Confirmation)
    }
    & $python @arguments
    if ($LASTEXITCODE -ne 0) {
        Stop-Blocked 'archive_memory_admin_failed'
    }
}
finally {
    $env:PYTHONPATH = $previousPythonPath
}

$evidence = Get-Content -LiteralPath $providerEvidence -Raw -Encoding UTF8 | ConvertFrom-Json
$hashPattern = '^[0-9a-f]{64}$'
if ($evidence.status -ne 'PASS' -or $evidence.provider -ne 'volcengine' -or
    $evidence.loopback_only -ne $true -or $evidence.credential_echoed -ne $false -or
    [int]$evidence.live_model_request_count -ne 3 -or
    [int]$evidence.builtin_toolset_enabled_count -ne 0 -or
    [int]$evidence.listener_count -ne 1 -or $evidence.unsupported_rejected -ne $true -or
    [string]$evidence.model_sha256 -cnotmatch $hashPattern -or
    [string]$evidence.count_plan_sha256 -cnotmatch $hashPattern -or
    [string]$evidence.search_plan_sha256 -cnotmatch $hashPattern) {
    Stop-Blocked 'provider_evidence_invalid'
}

foreach ($artifact in @(
        @{ Name = 'WINDOWS_DEBUG'; Path = $exe },
        @{ Name = 'ANDROID_DEBUG'; Path = $apk }
    )) {
    if (Test-Path -LiteralPath $artifact.Path -PathType Leaf) {
        $item = Get-Item -LiteralPath $artifact.Path
        $hash = (Get-FileHash -LiteralPath $artifact.Path -Algorithm SHA256).Hash
        Write-Output "$($artifact.Name)_READY=true"
        Write-Output "$($artifact.Name)_SIZE=$($item.Length)"
        Write-Output "$($artifact.Name)_SHA256=$hash"
    }
    else {
        Write-Output "$($artifact.Name)_READY=false"
    }
}
Write-Output 'S3_PROVIDER_EVIDENCE=PASS'
Write-Output "S3_ARCHIVE_RESET_PERFORMED=$($ResetArchiveMemory.IsPresent.ToString().ToLowerInvariant())"
