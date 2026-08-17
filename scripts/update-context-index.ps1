param([switch]$Check)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$utf8 = New-Object Text.UTF8Encoding($false)

function Hash-File([string]$path) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return 'missing' }
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
}
function Meta([string]$text, [string]$name) {
    $m = [regex]::Match($text, '(?m)^\s*' + [regex]::Escape($name) + '\s*=\s*"([^"]*)"')
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}
function Yaml([string]$value) {
    if ($null -eq $value) { return '""' }
    return '"' + (($value -replace '\\', '\\') -replace '"', '\"' -replace '[\r\n]+', ' ') + '"'
}
function Write-Generated([string]$path, [string[]]$lines, [ref]$stale) {
    $content = ($lines -join "`n") + "`n"
    $existing = if (Test-Path -LiteralPath $path -PathType Leaf) { [IO.File]::ReadAllText($path) -replace "`r`n", "`n" } else { '' }
    if ($existing -cne $content) {
        $stale.Value = $true
        if (-not $Check) {
            $directory = Split-Path -Parent $path
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
            [IO.File]::WriteAllText($path, $content, $utf8)
        }
    }
}

$registryPath = Join-Path $repoRoot 'registry/tools.yml'
$registryText = Get-Content -Raw -LiteralPath $registryPath
$toolBlocks = [regex]::Matches($registryText, '(?ms)^  - id:\s*(\S+).*?(?=^  - id:|\z)')
$workItems = [System.Collections.Generic.List[string]]::new()
$workItems.Add('schema_version: 1')
$workItems.Add('generated_from: [registry/tools.yml, manifests/*.yml, dependencies/**/*.yml]')
$workItems.Add('items:')
$stale = $false

foreach ($toolMatch in $toolBlocks) {
    $block = $toolMatch.Value
    $toolId = $toolMatch.Groups[1].Value
    $name = [regex]::Match($block, '(?m)^\s+name:\s*([^\r\n]+)').Groups[1].Value.Trim()
    $status = [regex]::Match($block, '(?m)^\s+status:\s*(\S+)').Groups[1].Value
    $revision = [regex]::Match($block, 'analyzed_revision:\s*([^\s}\r\n]+)').Groups[1].Value
    $coveragePath = Join-Path $repoRoot "coverage/$toolId.yml"
    $telemetryPath = Join-Path $repoRoot "telemetry/$toolId.md"
    $reportRelative = if ($toolId -eq 'rubeus') { 'RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md' } else { "reports/$toolId/source-analysis.md" }
    $reportPath = Join-Path $repoRoot $reportRelative
    $reviewPath = Join-Path $repoRoot "reviews/$toolId/detection-review.md"
    $translationReviewPath = Join-Path $repoRoot "reviews/$toolId/translation-review.md"
    $yaralDirectory = Join-Path $repoRoot "detections/$toolId/yaral"
    $rules = if (Test-Path -LiteralPath $yaralDirectory) { @(Get-ChildItem -LiteralPath $yaralDirectory -Filter '*.yaral' -File | Sort-Object Name) } else { @() }

    $procedureRows = @()
    $coverageText = ''
    if (Test-Path -LiteralPath $coveragePath) {
        $coverageText = Get-Content -Raw -LiteralPath $coveragePath
        $procedureRows = @([regex]::Matches($coverageText, '(?m)^\s*-\s*\{\s*id:\s*([^,}]+),\s*name:\s*([^,}]+).*?telemetry_status:\s*([^,}]+),\s*detection_status:\s*([^,}]+),\s*detection_rules:\s*\[([^\]]*)\]') | ForEach-Object {
            [pscustomobject]@{ Id=$_.Groups[1].Value.Trim(); Name=$_.Groups[2].Value.Trim(); Telemetry=$_.Groups[3].Value.Trim(); Detection=$_.Groups[4].Value.Trim(); Rules=$_.Groups[5].Value.Trim() }
        })
    }

    if ($procedureRows.Count -gt 0) {
        $summary = [System.Collections.Generic.List[string]]::new()
        $summary.Add("# $name procedure summary")
        $summary.Add('')
        $summary.Add('Generated context view. Use the coverage ledger and cited report as authoritative evidence.')
        $summary.Add('')
        $summary.Add("- Tool ID: $toolId")
        $summary.Add("- Revision: $revision")
        $summary.Add("- Lifecycle: $status")
        $summary.Add("- Full evidence: $reportRelative")
        $summary.Add("- Coverage ledger: coverage/$toolId.yml")
        $summary.Add('')
        $summary.Add('| Procedure | Summary | Telemetry | Detection | Canonical rules |')
        $summary.Add('| --- | --- | --- | --- | --- |')
        foreach ($p in $procedureRows) { $summary.Add("| $($p.Id) | $($p.Name -replace '\|','/') | $($p.Telemetry) | $($p.Detection) | $($p.Rules) |") }
        Write-Generated (Join-Path $repoRoot "summaries/$toolId.md") $summary ([ref]$stale)
    }

    $manifest = [System.Collections.Generic.List[string]]::new()
    $manifest.Add('schema_version: 1')
    $manifest.Add("tool_id: $toolId")
    $manifest.Add("name: $(Yaml $name)")
    $manifest.Add("lifecycle_status: $status")
    $manifest.Add("analyzed_revision: $(Yaml $revision)")
    $manifest.Add('context_entry_points:')
    $manifest.Add("  registry: registry/tools.yml")
    if ($procedureRows.Count) { $manifest.Add("  summary: summaries/$toolId.md") }
    if (Test-Path -LiteralPath $coveragePath) { $manifest.Add("  coverage: coverage/$toolId.yml") }
    if (Test-Path -LiteralPath $reportPath) { $manifest.Add("  report: $reportRelative") }
    if (Test-Path -LiteralPath $telemetryPath) { $manifest.Add("  telemetry: telemetry/$toolId.md") }
    $manifest.Add('counts:')
    $manifest.Add("  procedures: $($procedureRows.Count)")
    $manifest.Add("  canonical_rules: $($rules.Count)")
    foreach ($format in @('spl','kql','sql','eql','sigma')) {
        $extension = if ($format -eq 'sigma') { '*.yml' } else { "*.$format" }
        $count = if (Test-Path -LiteralPath (Join-Path $repoRoot "detections/$toolId/$format")) { @(Get-ChildItem -LiteralPath (Join-Path $repoRoot "detections/$toolId/$format") -Filter $extension -File).Count } else { 0 }
        $manifest.Add("  ${format}_translations: $count")
    }
    $allTranslationsPresent = $rules.Count -gt 0
    foreach ($format in @('spl','kql','sql','eql','sigma')) {
        $extension = if ($format -eq 'sigma') { '*.yml' } else { "*.$format" }
        $formatCount = if (Test-Path -LiteralPath (Join-Path $repoRoot "detections/$toolId/$format")) { @(Get-ChildItem -LiteralPath (Join-Path $repoRoot "detections/$toolId/$format") -Filter $extension -File).Count } else { 0 }
        if ($formatCount -ne $rules.Count) { $allTranslationsPresent = $false }
    }
    $unassessedCount = if ($coverageText) { [regex]::Match($coverageText, 'unassessed:\s*(\d+)').Groups[1].Value } else { '' }
    $validationCounts = @{}
    foreach ($ruleFile in $rules) {
        $vs = Meta (Get-Content -Raw -LiteralPath $ruleFile.FullName) 'validation_status'
        if (-not $vs) { $vs = 'unspecified' }
        if (-not $validationCounts.ContainsKey($vs)) { $validationCounts[$vs] = 0 }
        $validationCounts[$vs]++
    }
    $validationSummary = if ($validationCounts.Count) { (($validationCounts.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Value) $($_.Name)" }) -join ', ') } else { 'not_applicable' }
    $manifest.Add('completion_states:')
    $manifest.Add("  source_analysis: $(if ($status -eq 'analyzed') { 'complete' } elseif ($status -like 'blocked_*') { $status } else { 'incomplete' })")
    $manifest.Add("  canonical_detection: $(if ($rules.Count -gt 0 -and $unassessedCount -eq '0') { 'complete' } elseif ($rules.Count -gt 0) { 'in_progress' } else { 'not_started' })")
    $manifest.Add("  telemetry_reconciliation: $(if (Test-Path -LiteralPath $telemetryPath) { 'complete_for_experimental_rules' } else { 'not_started' })")
    $manifest.Add("  secondary_translation: $(if ($allTranslationsPresent) { 'draft_complete' } elseif ($rules.Count) { 'in_progress' } else { 'not_started' })")
    $manifest.Add("  rule_validation_labels: $(Yaml $validationSummary)")
    $manifest.Add('artifact_hashes:')
    $manifest.Add("  registry: $(Hash-File $registryPath)")
    if (Test-Path -LiteralPath $coveragePath) { $manifest.Add("  coverage: $(Hash-File $coveragePath)") }
    if (Test-Path -LiteralPath $reportPath) { $manifest.Add("  report: $(Hash-File $reportPath)") }
    if (Test-Path -LiteralPath $telemetryPath) { $manifest.Add("  telemetry: $(Hash-File $telemetryPath)") }
    if (Test-Path -LiteralPath $reviewPath) { $manifest.Add("  detection_review: $(Hash-File $reviewPath)") }
    if (Test-Path -LiteralPath $translationReviewPath) { $manifest.Add("  translation_review: $(Hash-File $translationReviewPath)") }
    $manifest.Add('rules:')

    foreach ($ruleFile in $rules) {
        $text = Get-Content -Raw -LiteralPath $ruleFile.FullName
        $ruleName = $ruleFile.BaseName
        $procedures = Meta $text 'procedure_ids'
        $severity = (Meta $text 'severity').ToLowerInvariant()
        $prerequisites = Meta $text 'log_source_prerequisites'
        $falsePositives = Meta $text 'false_positives'
        $references = Meta $text 'references'
        $description = Meta $text 'description'
        $validationStatus = Meta $text 'validation_status'
        $canonicalHash = Hash-File $ruleFile.FullName
        $eventTypes = [System.Collections.Generic.List[string]]::new()
        [regex]::Matches($text, '(?m)metadata\.(?:product_event_type|event_type)\s*=\s*"([^"]+)"') | ForEach-Object { $eventTypes.Add($_.Groups[1].Value) }
        [regex]::Matches($text, '(?m)metadata\.(?:product_event_type|event_type)\s*=\s*/([^/]+)/') | ForEach-Object { (($_.Groups[1].Value -replace '[()]','').Split('|')) | ForEach-Object { if ($_ -match '^[A-Za-z0-9_ -]+$') { $eventTypes.Add($_) } } }
        [regex]::Matches($text, '(?m)re\.regex\(\$[A-Za-z0-9_]+\.metadata\.(?:product_event_type|event_type),\s*`([^`]+)`\)') | ForEach-Object { (($_.Groups[1].Value -replace '[\^$()]','').Split('|')) | ForEach-Object { if ($_ -match '^[A-Za-z0-9_ -]+$') { $eventTypes.Add($_) } } }
        $eventTypes = @($eventTypes | Sort-Object -Unique)
        $fields = @([regex]::Matches($text, '\$[A-Za-z0-9_]+\.([A-Za-z0-9_.]+)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        $window = [regex]::Match($text, '(?m)^\s*match:?.*?\bover\s+([^\r\n]+)').Groups[1].Value.Trim()
        if (-not $window) { $window = [regex]::Match($text, '(?m)^\s*\$[^\r\n]+\s+over\s+([^\r\n]+)').Groups[1].Value.Trim() }
        $hasCorrelation = [regex]::Matches($text, '(?m)^\s*\$[A-Za-z0-9_]+\.metadata\.').Count -gt 1 -or $text -match '(?m)^\s*match:'
        $hasAggregation = $text -match '(?m)^\s*outcome:' -or $text -match 'count(?:_distinct)?\('
        $hasAbsence = $text -match '(?i)not\s+\$|!\$'

        $dependency = [System.Collections.Generic.List[string]]::new()
        $dependency.Add('schema_version: 1')
        $dependency.Add("tool_id: $toolId")
        $dependency.Add("rule_name: $ruleName")
        $dependency.Add("canonical_path: detections/$toolId/yaral/$($ruleFile.Name)")
        $dependency.Add("canonical_sha256: $canonicalHash")
        $dependency.Add("description: $(Yaml $description)")
        $dependency.Add("severity: $severity")
        $dependency.Add("procedure_ids: [$(($procedures.Split(',') | ForEach-Object { Yaml $_.Trim() }) -join ', ')]")
        $dependency.Add("validation_status: $(Yaml $validationStatus)")
        $dependency.Add("telemetry_prerequisites: $(Yaml $prerequisites)")
        $dependency.Add("atomic_event_types: [$(($eventTypes | ForEach-Object { Yaml $_ }) -join ', ')]")
        $dependency.Add("required_udm_fields: [$(($fields | ForEach-Object { Yaml $_ }) -join ', ')]")
        $dependency.Add("correlation_window: $(Yaml $window)")
        $dependency.Add("uses_multi_event_correlation: $($hasCorrelation.ToString().ToLowerInvariant())")
        $dependency.Add("uses_aggregation: $($hasAggregation.ToString().ToLowerInvariant())")
        $dependency.Add("uses_absence_logic: $($hasAbsence.ToString().ToLowerInvariant())")
        $dependency.Add("false_positives: $(Yaml $falsePositives)")
        $dependency.Add("references: $(Yaml $references)")
        $dependency.Add('translations:')
        foreach ($format in @('spl','kql','sql','eql','sigma')) {
            $extension = if ($format -eq 'sigma') { 'yml' } else { $format }
            $relative = "detections/$toolId/$format/$ruleName.$extension"
            $path = Join-Path $repoRoot $relative
            $translationText = if (Test-Path -LiteralPath $path) { Get-Content -Raw -LiteralPath $path } else { '' }
            $translationStatus = [regex]::Match($translationText, '(?m)^\s*(?:#|//|--)?\s*translation_status:\s*([^\s]+)').Groups[1].Value
            $fidelity = [regex]::Match($translationText, '(?m)^\s*(?:#|//|--)?\s*fidelity:\s*([^\s]+)').Groups[1].Value
            $dependency.Add("  ${format}: { path: $(Yaml $relative), sha256: $(Hash-File $path), status: $(Yaml $translationStatus), fidelity: $(Yaml $fidelity) }")
        }
        Write-Generated (Join-Path $repoRoot "dependencies/$toolId/$ruleName.yml") $dependency ([ref]$stale)

        $manifest.Add("  - { name: $ruleName, severity: $severity, procedures: $(Yaml $procedures), dependency: dependencies/$toolId/$ruleName.yml, canonical_sha256: $canonicalHash }")
    }
    if ($rules.Count -eq 0) { $manifest.Add('  []') }
    $blockerCount = if ($coverageText) { [regex]::Match($coverageText, 'blocked_source:\s*(\d+)').Groups[1].Value } else { '' }
    $manifest.Add('unresolved:')
    $manifest.Add("  source_blockers: $(if ($blockerCount) { $blockerCount } else { 0 })")
    Write-Generated (Join-Path $repoRoot "manifests/$toolId.yml") $manifest ([ref]$stale)
}

if ($workItems[-1] -eq 'items:') { $workItems.Add('  []') }
Write-Generated (Join-Path $repoRoot 'state/work-items.yml') $workItems ([ref]$stale)
if ($Check) {
    if ($stale) { throw 'Context index is stale; run scripts/update-context-index.ps1' }
    Write-Host 'Context index is current.'
} else {
    Write-Host 'Context index updated.'
}
