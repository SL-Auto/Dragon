[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$CatalogPath,
    [string[]]$SourceId,
    [switch]$Check
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $CatalogPath) { $CatalogPath = Join-Path $repoRoot 'public-rules/catalog.json' }
$publicRoot = Join-Path $repoRoot 'public-rules'
$cacheRoot = Join-Path $publicRoot '.cache'
$snapshotRoot = Join-Path $publicRoot 'snapshots'
$statePath = Join-Path $publicRoot 'state.json'
$forbiddenExtensions = @('.exe', '.dll', '.sys', '.scr', '.com', '.msi', '.jar', '.apk', '.bin', '.elf', '.pyc')

if (-not (Test-Path -LiteralPath $CatalogPath -PathType Leaf)) { throw "Missing public-rule catalog: $CatalogPath" }
$catalog = Get-Content -Raw -LiteralPath $CatalogPath | ConvertFrom-Json
if ($catalog.schema_version -ne 1) { throw "Unsupported public-rule catalog schema: $($catalog.schema_version)" }

$state = [ordered]@{ schema_version = 1; last_refresh_utc = $null; sources = [ordered]@{} }
if (Test-Path -LiteralPath $statePath) {
    $existing = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
    foreach ($property in $existing.sources.PSObject.Properties) { $state.sources[$property.Name] = $property.Value }
}

foreach ($source in $catalog.sources) {
    if (-not $source.enabled) { continue }
    if ($SourceId -and $source.id -notin $SourceId) { continue }
    if ($source.id -notmatch '^[a-z0-9][a-z0-9-]+$') { throw "Unsafe source id: $($source.id)" }
    if ($source.repository -notmatch '^https://github\.com/[^/]+/[^/]+(?:\.git)?$') { throw "Only allowlisted HTTPS GitHub repositories are supported: $($source.repository)" }
    $useWsl = $source.PSObject.Properties.Name.Contains('use_wsl') -and $source.use_wsl
    $cacheName = if ($useWsl) { "$($source.id)-wsl" } else { $source.id }
    $cachePath = Join-Path $cacheRoot $cacheName
    $wslCachePath = if ($useWsl) { (& wsl wslpath -a $cachePath).Trim() } else { $null }

    if (-not (Test-Path -LiteralPath $cachePath -PathType Container)) {
        if ($Check) { throw "Public-rule cache missing for enabled source '$($source.id)'" }
        New-Item -ItemType Directory -Force -Path $cacheRoot | Out-Null
        if ($useWsl) {
            & wsl git clone --filter=blob:none --no-checkout $source.repository $wslCachePath
        } else {
            & git clone --filter=blob:none --no-checkout $source.repository $cachePath
        }
        if ($LASTEXITCODE) { throw "git clone failed for $($source.id)" }
    }
    if ($useWsl) {
        & wsl git -C $wslCachePath fetch --quiet --prune origin $source.default_branch
    } else {
        & git -C $cachePath fetch --quiet --prune origin $source.default_branch
    }
    if ($LASTEXITCODE) { throw "git fetch failed for $($source.id)" }
    $commit = if ($useWsl) { (& wsl git -C $wslCachePath rev-parse "origin/$($source.default_branch)").Trim() } else { (& git -C $cachePath rev-parse "origin/$($source.default_branch)").Trim() }
    if ($commit -notmatch '^[0-9a-f]{40}$') { throw "Invalid commit returned for $($source.id): $commit" }
    $destination = Join-Path (Join-Path $snapshotRoot $source.id) $commit

    if (-not (Test-Path -LiteralPath $destination -PathType Container)) {
        if ($Check) { throw "Fresh public-rule snapshot missing: $($source.id)/$commit" }
        $stage = Join-Path $cacheRoot "$($source.id)-stage"
        if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
        New-Item -ItemType Directory -Force -Path $stage | Out-Null
        if ($useWsl) { & wsl git -C $wslCachePath sparse-checkout init --no-cone } else { & git -C $cachePath sparse-checkout init --no-cone }
        if ($LASTEXITCODE) { throw "Sparse-checkout initialization failed for $($source.id)" }
        if ($useWsl) { & wsl git -C $wslCachePath sparse-checkout set --no-cone -- @($source.include_paths) } else { & git -C $cachePath sparse-checkout set --no-cone -- @($source.include_paths) }
        if ($LASTEXITCODE) { throw "Sparse-checkout path selection failed for $($source.id)" }
        if ($useWsl) { & wsl git -C $wslCachePath checkout --quiet --detach $commit } else { & git -C $cachePath checkout --quiet --detach $commit }
        if ($LASTEXITCODE) { throw "Pinned checkout failed for $($source.id)" }
        foreach ($includePath in $source.include_paths) {
            $sourcePath = Join-Path $cachePath $includePath
            if (-not (Test-Path -LiteralPath $sourcePath)) { throw "Catalog path missing at pinned revision for $($source.id): $includePath" }
            $targetParent = Split-Path -Parent (Join-Path $stage $includePath)
            New-Item -ItemType Directory -Force -Path $targetParent | Out-Null
            Copy-Item -LiteralPath $sourcePath -Destination (Join-Path $stage $includePath) -Recurse
        }
        $allowed = @($source.extensions | ForEach-Object { $_.ToLowerInvariant() })
        $files = Get-ChildItem -LiteralPath $stage -Recurse -File
        foreach ($file in $files) {
            if ($forbiddenExtensions -contains $file.Extension.ToLowerInvariant()) { throw "Forbidden content in public source $($source.id): $($file.FullName)" }
            $relativePath = $file.FullName.Substring($stage.Length + 1).Replace('\', '/')
            $matchesDeclaredPath = $true
            if ($source.PSObject.Properties.Name.Contains('file_patterns')) {
                $matchesDeclaredPath = @($source.file_patterns | Where-Object { $relativePath -match $_ }).Count -gt 0
            }
            if ($allowed -notcontains $file.Extension.ToLowerInvariant() -or -not $matchesDeclaredPath) { Remove-Item -LiteralPath $file.FullName -Force }
        }
        New-Item -ItemType Directory -Force -Path $destination | Out-Null
        Get-ChildItem -LiteralPath $stage -Force | Copy-Item -Destination $destination -Recurse
        Remove-Item -LiteralPath $stage -Recurse -Force

        $manifestFiles = @(Get-ChildItem -LiteralPath $destination -Recurse -File | Sort-Object FullName | ForEach-Object {
            [ordered]@{
                path = $_.FullName.Substring($destination.Length + 1).Replace('\', '/')
                sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
                bytes = $_.Length
            }
        })
        $manifest = [ordered]@{
            schema_version = 1
            source_id = $source.id
            repository = $source.repository
            commit = $commit
            retrieved_utc = [DateTime]::UtcNow.ToString('o')
            license = $source.license
            license_url = $source.license_url
            declared_formats = @($source.formats)
            include_paths = @($source.include_paths)
            files = $manifestFiles
        }
        $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $destination 'snapshot-manifest.json') -Encoding utf8
    }
    $state.sources[$source.id] = [ordered]@{ commit = $commit; snapshot = "snapshots/$($source.id)/$commit" }
}

if ($SourceId) {
    $knownIds = @($catalog.sources | ForEach-Object { $_.id })
    foreach ($requestedId in $SourceId) {
        if ($requestedId -notin $knownIds) { throw "Unknown public-rule source id: $requestedId" }
    }
}

if (-not $Check) {
    $state.last_refresh_utc = [DateTime]::UtcNow.ToString('o')
    $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $statePath -Encoding utf8
}
Write-Host "Public-rule refresh complete for $($state.sources.Count) enabled sources."
