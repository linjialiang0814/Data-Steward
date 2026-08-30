[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)')]
    [string]$PrivateIpv4
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Stop-Blocked {
    param([Parameter(Mandatory = $true)][string]$Code)
    throw "BLOCKED:$Code"
}

$appRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $appRoot '..\..'))
$hubRoot = Join-Path $repoRoot 'services\steward_hub'
$python = Join-Path $hubRoot '.venv\Scripts\python.exe'
$exe = Join-Path $appRoot 'build\windows\x64\runner\Debug\steward_app.exe'
$hubData = Join-Path $env:LOCALAPPDATA 'DataSteward\hub'
$identityRoot = Join-Path $hubData 'tls-identity-v1'
$database = Join-Path $hubData 'steward.sqlite3'

$address = [System.Net.IPAddress]::Parse($PrivateIpv4)
if ($address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
    Stop-Blocked 'private_ipv4_required'
}
$bytes = $address.GetAddressBytes()
$isPrivate = ($bytes[0] -eq 10) -or
    ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
    ($bytes[0] -eq 192 -and $bytes[1] -eq 168)
if (-not $isPrivate) {
    Stop-Blocked 'private_ipv4_required'
}

$ipRows = @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $PrivateIpv4 |
        Where-Object { $_.AddressState -eq 'Preferred' })
if ($ipRows.Count -ne 1) {
    Stop-Blocked 'selected_adapter_not_unique_or_active'
}
$profiles = @(Get-NetConnectionProfile -InterfaceIndex $ipRows[0].InterfaceIndex)
if ($profiles.Count -ne 1 -or $profiles[0].NetworkCategory -ne 'Private') {
    Stop-Blocked 'network_profile_must_be_private'
}

foreach ($requiredFile in @($python, $exe)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        Stop-Blocked 'c2_runtime_file_missing'
    }
}
foreach ($requiredDirectory in @($hubRoot, $identityRoot)) {
    if (-not (Test-Path -LiteralPath $requiredDirectory -PathType Container)) {
        Stop-Blocked 'c2_runtime_directory_missing'
    }
}

$existingApp = @(Get-Process steward_app -ErrorAction SilentlyContinue)
if ($existingApp.Count -ne 0) {
    Stop-Blocked 'steward_app_already_running'
}

$names = @(
    'DATA_STEWARD_C2_SUPERVISED',
    'DATA_STEWARD_C2_PYTHON',
    'DATA_STEWARD_C2_HUB_ROOT',
    'DATA_STEWARD_C2_DATABASE',
    'DATA_STEWARD_C2_IDENTITY_ROOT',
    'DATA_STEWARD_C2_PRIVATE_IPV4'
)
$previous = @{}
foreach ($name in $names) {
    $previous[$name] = [System.Environment]::GetEnvironmentVariable($name, 'Process')
}
try {
    $env:DATA_STEWARD_C2_SUPERVISED = '1'
    $env:DATA_STEWARD_C2_PYTHON = $python
    $env:DATA_STEWARD_C2_HUB_ROOT = $hubRoot
    $env:DATA_STEWARD_C2_DATABASE = $database
    $env:DATA_STEWARD_C2_IDENTITY_ROOT = $identityRoot
    $env:DATA_STEWARD_C2_PRIVATE_IPV4 = $PrivateIpv4
    $process = Start-Process -FilePath $exe -PassThru
}
finally {
    foreach ($name in $names) {
        [System.Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process')
    }
}

Write-Output 'C2_PRIVATE_PROFILE_VERIFIED=true'
Write-Output "C2_APP_PID=$($process.Id)"
Write-Output 'C2_FIREWALL_MUTATION=false'
