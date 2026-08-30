[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$appRoot = Split-Path -Parent $PSScriptRoot
$initScript = Join-Path $appRoot "android\gradle\repository-mirrors.init.gradle"
$apkPath = Join-Path $appRoot "build\app\outputs\flutter-apk\app-debug.apk"
$gradleUserHome = Join-Path $env:USERPROFILE ".gradle"
$globalInitDirectory = Join-Path $gradleUserHome "init.d"
$globalInitScript = Join-Path $globalInitDirectory "data-steward-repository-mirrors.gradle"

if (-not (Test-Path -LiteralPath $initScript)) {
    throw "Gradle init script not found: $initScript"
}

$flutterCommand = Get-Command flutter -ErrorAction SilentlyContinue
if ($flutterCommand) {
    $flutterExecutable = $flutterCommand.Source
}
else {
    $flutterExecutable = Join-Path $env:USERPROFILE "flutter\bin\flutter.bat"
}

if (-not (Test-Path -LiteralPath $flutterExecutable)) {
    throw "Flutter executable was not found on PATH or at: $flutterExecutable"
}

$previousGradleOpts = $env:GRADLE_OPTS
$previousGradleUserHome = $env:GRADLE_USER_HOME
$previousPubHostedUrl = $env:PUB_HOSTED_URL
$previousFlutterStorageBaseUrl = $env:FLUTTER_STORAGE_BASE_URL

try {
    New-Item -ItemType Directory -Path $globalInitDirectory -Force | Out-Null
    Copy-Item -LiteralPath $initScript -Destination $globalInitScript -Force

    $mirrorOptIn = "-DdataSteward.useGoogleMirror=true"
    $env:GRADLE_OPTS = (($previousGradleOpts, $mirrorOptIn) |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join " "
    $env:GRADLE_USER_HOME = $gradleUserHome
    if ([string]::IsNullOrWhiteSpace($env:PUB_HOSTED_URL)) {
        $env:PUB_HOSTED_URL = "https://pub.flutter-io.cn"
    }
    if ([string]::IsNullOrWhiteSpace($env:FLUTTER_STORAGE_BASE_URL)) {
        $env:FLUTTER_STORAGE_BASE_URL = "https://storage.flutter-io.cn"
    }

    Push-Location $appRoot
    try {
        Write-Host "Installed opt-in Gradle repository mirror init script:"
        Write-Host "  $globalInitScript"
        Write-Host "Mirror activation: $mirrorOptIn"

        Write-Host "Flutter executable: $flutterExecutable"

        & $flutterExecutable build apk --debug
        if ($LASTEXITCODE -ne 0) {
            throw "flutter build apk --debug failed with exit code $LASTEXITCODE"
        }

        if (-not (Test-Path -LiteralPath $apkPath)) {
            throw "Build reported success but APK was not found: $apkPath"
        }

        $apk = Get-Item -LiteralPath $apkPath
        $hash = Get-FileHash -LiteralPath $apkPath -Algorithm SHA256

        Write-Host ""
        Write-Host "Debug APK verified:"
        Write-Host "  Path: $($apk.FullName)"
        Write-Host "  Size: $($apk.Length) bytes"
        Write-Host "  SHA-256: $($hash.Hash)"
    }
    finally {
        Pop-Location
    }
}
finally {
    $env:GRADLE_OPTS = $previousGradleOpts
    $env:GRADLE_USER_HOME = $previousGradleUserHome
    $env:PUB_HOSTED_URL = $previousPubHostedUrl
    $env:FLUTTER_STORAGE_BASE_URL = $previousFlutterStorageBaseUrl
}
