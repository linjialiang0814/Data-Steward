[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Stop-Blocked {
    param([Parameter(Mandatory = $true)][string]$Code)
    throw "BLOCKED:$Code"
}

function Assert-RegularFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Stop-Blocked 'artifact_missing'
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Stop-Blocked 'artifact_reparse_point'
    }
}

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd('\')
$pubspec = Join-Path $repoRoot 'apps\steward_app\pubspec.yaml'
$windowsSource = Join-Path $repoRoot 'build\delivery\windows\Release'
$androidSource = Join-Path $repoRoot 'build\delivery\android\DataSteward-Android-Demo.apk'
$outputRoot = Join-Path $repoRoot 'dist'

if (-not (Test-Path -LiteralPath $pubspec -PathType Leaf)) {
    Stop-Blocked 'pubspec_missing'
}
$versionMatch = Select-String -LiteralPath $pubspec -Pattern '^version:\s*([0-9]+\.[0-9]+\.[0-9]+\+[0-9]+)\s*$'
if (@($versionMatch).Count -ne 1) {
    Stop-Blocked 'version_not_unique'
}
$version = $versionMatch.Matches[0].Groups[1].Value

$status = @(& git -C $repoRoot status --porcelain)
if ($LASTEXITCODE -ne 0 -or $status.Count -ne 0) {
    Stop-Blocked 'worktree_not_clean'
}
$commit = (& git -C $repoRoot rev-parse HEAD).Trim()
$branch = (& git -C $repoRoot branch --show-current).Trim()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    Stop-Blocked 'git_identity_unavailable'
}
$shortCommit = $commit.Substring(0, 7)

if (-not (Test-Path -LiteralPath $windowsSource -PathType Container)) {
    Stop-Blocked 'windows_bundle_missing'
}
$windowsRootItem = Get-Item -LiteralPath $windowsSource -Force
if (($windowsRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    Stop-Blocked 'windows_bundle_reparse_point'
}
$windowsFiles = @(Get-ChildItem -LiteralPath $windowsSource -Recurse -File -Force)
if ($windowsFiles.Count -ne 14) {
    Stop-Blocked 'windows_bundle_file_count_changed'
}
$reparseFiles = @($windowsFiles | Where-Object {
        ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    })
if ($reparseFiles.Count -ne 0) {
    Stop-Blocked 'windows_bundle_contains_reparse_point'
}
$forbiddenWindowsFiles = @($windowsFiles | Where-Object {
        $_.Extension -in @('.pdb', '.ilk', '.lib', '.exp')
    })
if ($forbiddenWindowsFiles.Count -ne 0) {
    Stop-Blocked 'windows_bundle_contains_debug_artifact'
}

$windowsExe = Join-Path $windowsSource 'steward_app.exe'
$windowsApp = Join-Path $windowsSource 'data\app.so'
Assert-RegularFile $windowsExe
Assert-RegularFile $windowsApp
Assert-RegularFile $androidSource

$expectedExeSha256 = 'F5F82C40B33589E8C90AE67E2B7F591F471FF8238308D5BA4D96D370F11E110E'
$expectedAppSha256 = 'CB752B726C3A1483DF8AF2E25C5E062761F9D4C45A948DD2E8CA9B7C0D248AB5'
$expectedApkSha256 = '8D957D3BD932D0D9D30B4CE7D27A9A74FEAE9383DD4B6EA258362EE63638A796'
$exeSha256 = (Get-FileHash -LiteralPath $windowsExe -Algorithm SHA256).Hash
$appSha256 = (Get-FileHash -LiteralPath $windowsApp -Algorithm SHA256).Hash
$apkSha256 = (Get-FileHash -LiteralPath $androidSource -Algorithm SHA256).Hash
if ($exeSha256 -ne $expectedExeSha256 -or
    $appSha256 -ne $expectedAppSha256 -or
    $apkSha256 -ne $expectedApkSha256) {
    Stop-Blocked 'artifact_hash_changed'
}

$packageName = "DataSteward-App-Demo-$version-$shortCommit"
$packageRoot = Join-Path $outputRoot $packageName
$zipPath = Join-Path $outputRoot "$packageName.zip"
$zipHashPath = "$zipPath.sha256.txt"
foreach ($path in @($packageRoot, $zipPath, $zipHashPath)) {
    if (Test-Path -LiteralPath $path) {
        Stop-Blocked 'delivery_output_already_exists'
    }
}

$stageRoot = Join-Path $outputRoot ('.packaging-' + [guid]::NewGuid().ToString('N'))
$stagePackage = Join-Path $stageRoot $packageName
$utf8 = New-Object Text.UTF8Encoding($false)
try {
    New-Item -ItemType Directory -Path (Join-Path $stagePackage 'windows') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $stagePackage 'android') -Force | Out-Null
    foreach ($item in Get-ChildItem -LiteralPath $windowsSource -Force) {
        Copy-Item -LiteralPath $item.FullName `
            -Destination (Join-Path $stagePackage 'windows') -Recurse -Force
    }
    Copy-Item -LiteralPath $androidSource `
        -Destination (Join-Path $stagePackage 'android\DataSteward-Android-Demo.apk')

    $readme = @"
# Data Steward APP Demo $version

This package is bound to source commit $commit on branch $branch.

## Android

- Install android/DataSteward-Android-Demo.apk on the authorized Android device.
- Package: io.datasteward.app; version: 1.0.0 (1); minimum SDK: 24.
- The APK is a Release build signed with the Android Debug certificate for the
  training-camp demo. It is not a store-production signing configuration.

## Windows

- windows/steward_app.exe is the complete Flutter Windows Release bundle.
- Keep every file under windows/ together; do not copy the EXE alone.
- The full cross-device demo still requires the repository's supervised local
  Hub/Hermes runtime, prepared Python virtual environments, permanent local TLS
  identity, and a provider credential supplied only through the current process.
- Start the authoritative full demo from the source workspace with
  apps/steward_app/tool/start_c3_windows_demo.ps1. Secrets, local TLS identity,
  SQLite state, Python virtual environments, and user files are deliberately not
  included in this archive.

## Integrity

Verify files with SHA256SUMS.txt. The outer ZIP hash is stored beside the ZIP.
This package contains no APK source fixture, real user material, API key, model
endpoint, TLS private key, SQLite database, cache, or debug symbol file.
"@
    [IO.File]::WriteAllText((Join-Path $stagePackage 'README.md'), $readme, $utf8)

    $manifest = [ordered]@{
        schema_version = 1
        product = 'Data Steward'
        package_kind = 'training_camp_app_demo'
        app_version = $version
        source_commit = $commit
        source_branch = $branch
        windows = [ordered]@{
            configuration = 'Release'
            file_count = $windowsFiles.Count
            bundle_size = ($windowsFiles | Measure-Object Length -Sum).Sum
            executable_sha256 = $exeSha256
            app_so_sha256 = $appSha256
        }
        android = [ordered]@{
            configuration = 'Release'
            signing = 'Android Debug certificate (demo only)'
            package_id = 'io.datasteward.app'
            version_name = '1.0.0'
            version_code = 1
            min_sdk = 24
            target_sdk = 36
            apk_size = (Get-Item -LiteralPath $androidSource).Length
            apk_sha256 = $apkSha256
        }
        excluded = @(
            'API credentials',
            'model endpoint identifiers',
            'TLS private identity',
            'SQLite state',
            'Python virtual environments',
            'user files',
            'debug symbols'
        )
    }
    [IO.File]::WriteAllText(
        (Join-Path $stagePackage 'manifest.json'),
        ($manifest | ConvertTo-Json -Depth 5),
        $utf8
    )

    $hashLines = @(
        Get-ChildItem -LiteralPath $stagePackage -Recurse -File |
            Sort-Object FullName |
            ForEach-Object {
                $relative = $_.FullName.Substring($stagePackage.Length + 1).Replace('\', '/')
                $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
                "$hash  $relative"
            }
    )
    [IO.File]::WriteAllLines(
        (Join-Path $stagePackage 'SHA256SUMS.txt'),
        $hashLines,
        $utf8
    )

    New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
    Move-Item -LiteralPath $stagePackage -Destination $packageRoot
    Compress-Archive -LiteralPath $packageRoot -DestinationPath $zipPath -CompressionLevel Optimal
    $zipSha256 = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
    [IO.File]::WriteAllText(
        $zipHashPath,
        "$zipSha256  $([IO.Path]::GetFileName($zipPath))`n",
        $utf8
    )
}
finally {
    if (Test-Path -LiteralPath $stageRoot) {
        $resolvedStage = [IO.Path]::GetFullPath($stageRoot)
        $resolvedOutput = [IO.Path]::GetFullPath($outputRoot).TrimEnd('\')
        if (-not $resolvedStage.StartsWith(
            $resolvedOutput + '\.packaging-',
            [StringComparison]::OrdinalIgnoreCase
        )) {
            Stop-Blocked 'packaging_cleanup_path_escape'
        }
        Remove-Item -LiteralPath $resolvedStage -Recurse -Force
    }
}

Write-Output 'PACKAGE_STATUS=PASS'
Write-Output "PACKAGE_ROOT=$packageRoot"
Write-Output "PACKAGE_ZIP=$zipPath"
Write-Output "PACKAGE_ZIP_SIZE=$((Get-Item -LiteralPath $zipPath).Length)"
Write-Output "PACKAGE_ZIP_SHA256=$zipSha256"
Write-Output "SOURCE_COMMIT=$commit"
