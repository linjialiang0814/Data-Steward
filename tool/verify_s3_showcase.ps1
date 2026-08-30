[CmdletBinding()]
param(
    [switch]$BuildArtifacts
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][scriptblock]$Command
    )
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "BLOCKED:$Label"
    }
    Write-Output "S3D_$Label=PASS"
}

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$hubRoot = Join-Path $repoRoot 'services\steward_hub'
$agentRoot = Join-Path $repoRoot 'agents\hermes_runtime'
$appRoot = Join-Path $repoRoot 'apps\steward_app'
$hubPython = Join-Path $hubRoot '.venv\Scripts\python.exe'
$agentPython = Join-Path $agentRoot '.venv\Scripts\python.exe'
$evidencePath = Join-Path $repoRoot 'docs\evidence\P0-S3-B\volcengine-live-provider-gate.json'

foreach ($required in @($hubPython, $agentPython, $evidencePath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw 'BLOCKED:s3d_required_input_missing'
    }
}
if (@(Get-Process steward_app -ErrorAction SilentlyContinue).Count -ne 0) {
    throw 'BLOCKED:steward_app_must_be_stopped'
}

$evidence = Get-Content -LiteralPath $evidencePath -Raw -Encoding UTF8 | ConvertFrom-Json
$hashPattern = '^[0-9a-f]{64}$'
if ($evidence.status -ne 'PASS' -or $evidence.provider -ne 'volcengine' -or
    $evidence.loopback_only -ne $true -or $evidence.credential_echoed -ne $false -or
    [int]$evidence.live_model_request_count -ne 3 -or
    [int]$evidence.builtin_toolset_enabled_count -ne 0 -or
    [int]$evidence.listener_count -ne 1 -or $evidence.unsupported_rejected -ne $true -or
    [string]$evidence.model_sha256 -cnotmatch $hashPattern -or
    [string]$evidence.count_plan_sha256 -cnotmatch $hashPattern -or
    [string]$evidence.search_plan_sha256 -cnotmatch $hashPattern) {
    throw 'BLOCKED:provider_evidence_invalid'
}
Write-Output 'S3D_PROVIDER_EVIDENCE=PASS'

$previousPythonPath = $env:PYTHONPATH
try {
    Push-Location $hubRoot
    try {
        $env:PYTHONPATH = 'src'
        Invoke-Checked 'HUB_FOCUSED_TESTS' {
            & $hubPython -m unittest `
                tests.test_agent_adapter `
                tests.test_agent_planning `
                tests.test_pc_file_scope `
                tests.test_device_auth_rest `
                tests.test_c3_supervised_shared_session_runtime `
                tests.test_archive_memory `
                tests.test_archive_memory_demo
        }
    }
    finally {
        Pop-Location
    }

    Push-Location $agentRoot
    try {
        $env:PYTHONPATH = '.'
        Invoke-Checked 'HERMES_GATE_TESTS' {
            & $agentPython -m unittest tests.test_volcengine_provider_gate
        }
    }
    finally {
        Pop-Location
    }
}
finally {
    $env:PYTHONPATH = $previousPythonPath
}

Push-Location $appRoot
try {
    Invoke-Checked 'FLUTTER_ANALYZE' { & flutter analyze --no-pub }
    Invoke-Checked 'FLUTTER_FOCUSED_TESTS' {
        & flutter test --no-pub `
            test/shared_session_ui/shared_session_controller_test.dart `
            test/shared_session_ui/shared_session_controller_r1_test.dart `
            test/shared_session_ui/shared_session_page_test.dart `
            test/shared_session_ui/mobile_authenticated_session_page_test.dart `
            test/shared_session_ui/pc_file_scope_panel_test.dart
    }
}
finally {
    Pop-Location
}

if ($BuildArtifacts) {
    Invoke-Checked 'WINDOWS_BUILD' {
        & (Join-Path $appRoot 'tool\build_windows_debug.ps1')
    }
    Invoke-Checked 'ANDROID_BUILD' {
        & (Join-Path $appRoot 'tool\build_android_debug.ps1')
    }
}

if (@(Get-Process steward_app -ErrorAction SilentlyContinue).Count -ne 0) {
    throw 'BLOCKED:steward_app_process_leaked'
}
Write-Output "S3D_BUILD_ARTIFACTS=$($BuildArtifacts.IsPresent.ToString().ToLowerInvariant())"
Write-Output 'S3D_OFFLINE_ACCEPTANCE=PASS'
