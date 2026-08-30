$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Stop-Blocked {
    param([Parameter(Mandatory = $true)][string]$Code)
    throw "BLOCKED:$Code"
}

try {
    $appRoot = [System.IO.Path]::GetFullPath(
        (Join-Path -Path $PSScriptRoot -ChildPath '..')
    ).TrimEnd('\')
    $metadataPath = Join-Path -Path $appRoot -ChildPath '.flutter-plugins-dependencies'
    if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) {
        Stop-Blocked 'plugin_metadata_missing'
    }

    $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
    if ($null -eq $metadata.plugins -or $null -eq $metadata.plugins.windows) {
        Stop-Blocked 'windows_plugin_metadata_missing'
    }
    $plugins = @($metadata.plugins.windows)
    $names = @{}

    $junctionRoot = [System.IO.Path]::GetFullPath(
        (Join-Path -Path $appRoot -ChildPath 'windows\flutter\ephemeral\.plugin_symlinks')
    ).TrimEnd('\')
    $expectedRoot = [System.IO.Path]::GetFullPath(
        (Join-Path -Path $appRoot -ChildPath 'windows\flutter\ephemeral\.plugin_symlinks')
    ).TrimEnd('\')
    if (-not [string]::Equals(
        $junctionRoot,
        $expectedRoot,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        Stop-Blocked 'junction_root_mismatch'
    }

    if (Test-Path -LiteralPath $junctionRoot) {
        $rootItem = Get-Item -LiteralPath $junctionRoot -Force
        if (-not $rootItem.PSIsContainer -or
            (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
            Stop-Blocked 'junction_root_unsafe'
        }
    }
    else {
        New-Item -ItemType Directory -Path $junctionRoot | Out-Null
    }

    foreach ($plugin in $plugins) {
        $name = [string]$plugin.name
        if ([string]::IsNullOrWhiteSpace($name) -or
            $name -notmatch '^[A-Za-z0-9_][A-Za-z0-9_.-]*$' -or
            $name.Contains('..') -or
            $name.Contains('\') -or
            $name.Contains('/')) {
            Stop-Blocked 'plugin_name_unsafe'
        }
        if ($names.ContainsKey($name)) {
            Stop-Blocked 'plugin_name_duplicate'
        }
        $names[$name] = $true

        $rawTarget = [string]$plugin.path
        if ([string]::IsNullOrWhiteSpace($rawTarget) -or
            $rawTarget.StartsWith('\\')) {
            Stop-Blocked 'plugin_target_unsafe'
        }
        $target = [System.IO.Path]::GetFullPath($rawTarget).TrimEnd('\')
        if (-not [System.IO.Path]::IsPathRooted($target) -or
            -not (Test-Path -LiteralPath $target -PathType Container)) {
            Stop-Blocked 'plugin_target_missing'
        }
        $workspacePrefix = "$appRoot\"
        if ($target.StartsWith(
            $workspacePrefix,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or [string]::Equals(
            $target,
            $appRoot,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            Stop-Blocked 'plugin_target_inside_workspace'
        }

        $junction = [System.IO.Path]::GetFullPath(
            (Join-Path -Path $junctionRoot -ChildPath $name)
        )
        $junctionParent = [System.IO.Path]::GetDirectoryName($junction).TrimEnd('\')
        if (-not [string]::Equals(
            $junctionParent,
            $junctionRoot,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            Stop-Blocked 'junction_path_escape'
        }

        if (Test-Path -LiteralPath $junction) {
            $existing = Get-Item -LiteralPath $junction -Force
            $isReparsePoint =
                (($existing.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
            $allowedLinkTypes = @('Junction', 'SymbolicLink')
            if (-not $isReparsePoint -or $existing.LinkType -notin $allowedLinkTypes) {
                Stop-Blocked 'existing_plugin_path_unsafe'
            }
            $existingTargets = @($existing.Target)
            if ($existingTargets.Count -ne 1) {
                Stop-Blocked 'existing_plugin_target_ambiguous'
            }
            $existingTarget = [System.IO.Path]::GetFullPath(
                [string]$existingTargets[0]
            ).TrimEnd('\')
            if (-not [string]::Equals(
                $existingTarget,
                $target,
                [System.StringComparison]::OrdinalIgnoreCase
            )) {
                Remove-Item -LiteralPath $junction -Force
                New-Item -ItemType Junction -Path $junction -Target $target | Out-Null
            }
        }
        else {
            New-Item -ItemType Junction -Path $junction -Target $target | Out-Null
        }
    }

    $pluginNames = @($names.Keys | Sort-Object)
    Write-Output "WINDOWS_PLUGIN_COUNT=$($pluginNames.Count)"
    Write-Output "WINDOWS_PLUGIN_NAMES=$($pluginNames -join ',')"

    # Flutter 3.44 may emit an unconditional CMake install rule for this
    # directory while producing no Windows native assets. Keep the generated
    # source directory present so an empty native-assets set installs cleanly.
    $nativeAssetsParent = [System.IO.Path]::GetFullPath(
        (Join-Path -Path $appRoot -ChildPath 'build\native_assets')
    ).TrimEnd('\')
    $nativeAssetsWindows = [System.IO.Path]::GetFullPath(
        (Join-Path -Path $nativeAssetsParent -ChildPath 'windows')
    ).TrimEnd('\')
    $expectedNativeAssetsParent = [System.IO.Path]::GetFullPath(
        (Join-Path -Path $appRoot -ChildPath 'build\native_assets')
    ).TrimEnd('\')
    if (-not [string]::Equals(
        $nativeAssetsParent,
        $expectedNativeAssetsParent,
        [System.StringComparison]::OrdinalIgnoreCase
    ) -or -not [string]::Equals(
        [System.IO.Path]::GetDirectoryName($nativeAssetsWindows).TrimEnd('\'),
        $nativeAssetsParent,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        Stop-Blocked 'native_assets_path_escape'
    }
    New-Item -ItemType Directory -Path $nativeAssetsWindows -Force | Out-Null

    Push-Location $appRoot
    try {
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        & flutter build windows --debug --no-pub
        $buildExit = $LASTEXITCODE
        $stopwatch.Stop()
    }
    finally {
        Pop-Location
    }
    if ($buildExit -ne 0) {
        Stop-Blocked 'flutter_build_failed'
    }

    $bundleRoot = [System.IO.Path]::GetFullPath(
        (Join-Path -Path $appRoot -ChildPath 'build\windows\x64\runner\Debug')
    ).TrimEnd('\')
    $exePath = [System.IO.Path]::GetFullPath(
        (Join-Path -Path $bundleRoot -ChildPath 'steward_app.exe')
    )
    $kernelPath = [System.IO.Path]::GetFullPath(
        (Join-Path -Path $bundleRoot -ChildPath 'data\flutter_assets\kernel_blob.bin')
    )
    $bundlePrefix = "$bundleRoot\"
    if (-not $exePath.StartsWith(
        $bundlePrefix,
        [System.StringComparison]::OrdinalIgnoreCase
    ) -or -not $kernelPath.StartsWith(
        $bundlePrefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        Stop-Blocked 'debug_bundle_path_escape'
    }
    if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
        Stop-Blocked 'windows_exe_missing'
    }
    if (-not (Test-Path -LiteralPath $kernelPath -PathType Leaf)) {
        Stop-Blocked 'kernel_blob_missing'
    }
    $exe = Get-Item -LiteralPath $exePath
    $kernel = Get-Item -LiteralPath $kernelPath
    if ($exe.PSIsContainer -or $kernel.PSIsContainer -or
        (($exe.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) -or
        (($kernel.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
        Stop-Blocked 'debug_bundle_artifact_not_regular_file'
    }
    $exeSha256 = (Get-FileHash -LiteralPath $exePath -Algorithm SHA256).Hash
    $kernelSha256 = (Get-FileHash -LiteralPath $kernelPath -Algorithm SHA256).Hash
    Write-Output "BUILD_SECONDS=$([math]::Round($stopwatch.Elapsed.TotalSeconds, 2))"
    Write-Output "EXE_PATH=$($exe.FullName)"
    Write-Output "EXE_SIZE=$($exe.Length)"
    Write-Output "EXE_SHA256=$exeSha256"
    Write-Output "KERNEL_BLOB_PATH=$($kernel.FullName)"
    Write-Output "KERNEL_BLOB_SIZE=$($kernel.Length)"
    Write-Output "KERNEL_BLOB_SHA256=$kernelSha256"
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
