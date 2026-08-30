[CmdletBinding()]
param(
    [AllowEmptyString()]
    [ValidatePattern('^(|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)')]
    [string]$PrivateIpv4 = '',

    [ValidateRange(1, 65535)]
    [int]$PrivatePort = 9443,

    [ValidateSet('', 'openrouter', 'openai', 'deepseek', 'dashscope', 'volcengine')]
    [string]$HermesProvider = '',

    [ValidatePattern('^[A-Za-z0-9._:/-]{0,128}$')]
    [string]$HermesModel = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Stop-Blocked {
    param([Parameter(Mandatory = $true)][string]$Code)
    throw "BLOCKED:$Code"
}

function Test-PrivateIpv4 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Value, [ref]$parsed)) {
        return $false
    }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return $false
    }
    $octets = $parsed.GetAddressBytes()
    return $octets[0] -eq 10 -or
        ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or
        ($octets[0] -eq 192 -and $octets[1] -eq 168)
}

$appRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $appRoot '..\..'))
$hubRoot = Join-Path $repoRoot 'services\steward_hub'
$python = Join-Path $hubRoot '.venv\Scripts\python.exe'
$exe = Join-Path $appRoot 'build\windows\x64\runner\Debug\steward_app.exe'
$hubData = Join-Path $env:LOCALAPPDATA 'DataSteward\hub'
$identityRoot = Join-Path $hubData 'tls-identity-v1'
$database = Join-Path $hubData 'steward.sqlite3'

$autoSelected = [string]::IsNullOrWhiteSpace($PrivateIpv4)
$privateProfiles = @(Get-NetConnectionProfile |
        Where-Object { $_.NetworkCategory -eq 'Private' })
$ipRows = @(
    foreach ($profile in $privateProfiles) {
        Get-NetIPAddress -InterfaceIndex $profile.InterfaceIndex -AddressFamily IPv4 `
            -ErrorAction SilentlyContinue |
            Where-Object {
                $_.AddressState -eq 'Preferred' -and
                -not $_.SkipAsSource -and
                (Test-PrivateIpv4 $_.IPAddress) -and
                ([string]::IsNullOrWhiteSpace($PrivateIpv4) -or
                    $_.IPAddress -eq $PrivateIpv4)
            }
    }
)
$ipRows = @($ipRows | Sort-Object IPAddress, InterfaceIndex -Unique)
if ($ipRows.Count -ne 1) {
    Stop-Blocked 'selected_adapter_not_unique_or_active'
}
$PrivateIpv4 = $ipRows[0].IPAddress
foreach ($requiredFile in @($python, $exe)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        Stop-Blocked 'c3_runtime_file_missing'
    }
}
foreach ($requiredDirectory in @($hubRoot, $identityRoot)) {
    if (-not (Test-Path -LiteralPath $requiredDirectory -PathType Container)) {
        Stop-Blocked 'c3_runtime_directory_missing'
    }
}
if (@(Get-Process steward_app -ErrorAction SilentlyContinue).Count -ne 0) {
    Stop-Blocked 'steward_app_already_running'
}
if ([string]::IsNullOrWhiteSpace($HermesProvider) -ne
    [string]::IsNullOrWhiteSpace($HermesModel)) {
    Stop-Blocked 'hermes_provider_model_pair_required'
}
if (-not [string]::IsNullOrWhiteSpace($HermesProvider)) {
    $credentialNames = @{
        openrouter = 'OPENROUTER_API_KEY'
        openai = 'OPENAI_API_KEY'
        deepseek = 'DEEPSEEK_API_KEY'
        dashscope = 'DASHSCOPE_API_KEY'
        volcengine = 'ARK_API_KEY'
    }
    $credentialName = $credentialNames[$HermesProvider]
    $credential = [System.Environment]::GetEnvironmentVariable(
        $credentialName,
        'Process'
    )
    if ([string]::IsNullOrWhiteSpace($credential)) {
        Stop-Blocked 'hermes_credential_missing'
    }
}

$names = @(
    'DATA_STEWARD_C3_SUPERVISED',
    'DATA_STEWARD_C3_PYTHON',
    'DATA_STEWARD_C3_HUB_ROOT',
    'DATA_STEWARD_C3_DATABASE',
    'DATA_STEWARD_C3_IDENTITY_ROOT',
    'DATA_STEWARD_C3_PRIVATE_IPV4',
    'DATA_STEWARD_C3_PRIVATE_PORT',
    'DATA_STEWARD_C3_HERMES_PROVIDER',
    'DATA_STEWARD_C3_HERMES_MODEL'
)
$previous = @{}
foreach ($name in $names) {
    $previous[$name] = [System.Environment]::GetEnvironmentVariable($name, 'Process')
}
try {
    $env:DATA_STEWARD_C3_SUPERVISED = '1'
    $env:DATA_STEWARD_C3_PYTHON = $python
    $env:DATA_STEWARD_C3_HUB_ROOT = $hubRoot
    $env:DATA_STEWARD_C3_DATABASE = $database
    $env:DATA_STEWARD_C3_IDENTITY_ROOT = $identityRoot
    $env:DATA_STEWARD_C3_PRIVATE_IPV4 = $PrivateIpv4
    $env:DATA_STEWARD_C3_PRIVATE_PORT = "$PrivatePort"
    $env:DATA_STEWARD_C3_HERMES_PROVIDER = $HermesProvider
    $env:DATA_STEWARD_C3_HERMES_MODEL = $HermesModel
    $process = Start-Process -FilePath $exe -PassThru
}
finally {
    foreach ($name in $names) {
        [System.Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process')
    }
}

Write-Output 'C3_PRIVATE_PROFILE_VERIFIED=true'
Write-Output "C3_PRIVATE_IPV4_AUTO_SELECTED=$($autoSelected.ToString().ToLowerInvariant())"
Write-Output "C3_APP_PID=$($process.Id)"
Write-Output "C3_SERVICE_PORT=$PrivatePort"
Write-Output 'C3_FIREWALL_MUTATION=false'
