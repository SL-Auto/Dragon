param([switch]$Check)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$masterPath = Join-Path $repoRoot 'telemetry/MASTER.md'
$registryText = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'registry/tools.yml')

$toolNames = @{}
[regex]::Matches($registryText, '(?ms)^  - id:\s*(\S+)\s*\r?\n\s+name:\s*([^\r\n]+)') | ForEach-Object {
    $toolNames[$_.Groups[1].Value] = $_.Groups[2].Value.Trim()
}

$rules = @{}
Get-ChildItem -LiteralPath (Join-Path $repoRoot 'detections') -Recurse -Filter '*.yaral' -File | ForEach-Object {
    $text = Get-Content -Raw -LiteralPath $_.FullName
    $name = [regex]::Match($text, '(?m)^rule\s+([A-Za-z0-9_]+)').Groups[1].Value
    $severity = [regex]::Match($text, '(?m)^\s*severity\s*=\s*"([^"]+)"').Groups[1].Value.ToUpperInvariant()
    $toolId = $_.Directory.Parent.Name
    if (-not $rules.ContainsKey($toolId)) { $rules[$toolId] = @() }
    $rules[$toolId] += [pscustomobject]@{ Name = $name; Severity = $severity; Text = $text }
}

$aliases = @{
    'Windows Security|4624' = @('4624', 'USER_LOGIN')
    'Windows Security|4688' = @('4688', 'PROCESS_LAUNCH')
    'Microsoft Sysmon|1' = @('PROCESS_LAUNCH')
    'Microsoft Sysmon|2' = @('FILE_CREATION_TIME', 'FILE_MODIFICATION')
    'Microsoft Sysmon|3' = @('NETWORK_CONNECTION')
    'Microsoft Sysmon|7' = @('MODULE_LOAD')
    'Microsoft Sysmon|10' = @('PROCESS_OPEN', 'PROCESS_ACCESS')
    'Microsoft Sysmon|11' = @('FILE_CREATION')
    'Microsoft Sysmon|12' = @('REGISTRY_CREATION', 'REGISTRY_DELETION')
    'Microsoft Sysmon|13' = @('REGISTRY_MODIFICATION')
    'Microsoft Sysmon|14' = @('REGISTRY_MODIFICATION')
    'Microsoft Sysmon|17' = @('NAMED_PIPE_CREATION')
    'Microsoft Sysmon|18' = @('NAMED_PIPE_CONNECTION')
    'Microsoft Sysmon|23' = @('FILE_DELETION')
    'Microsoft Sysmon|26' = @('FILE_DELETION')
}

function Test-RuleDependency([string]$text, [string]$provider, [string]$eventType) {
    # A telemetry dependency is expressed by the rule's events-section predicates or by its
    # documented normalized aliases in log_source_prerequisites. Other meta prose (description,
    # false positives, validation notes) must not create one, and event identifiers are matched
    # case-sensitively so ordinary words such as "path" cannot match an event type such as PATH.
    $events = [regex]::Match($text, '(?ms)^\s*events:[^\n]*\n(.*?)^\s*(match|outcome|condition|options):').Groups[1].Value
    $prerequisites = [regex]::Match($text, '(?m)^\s*log_source_prerequisites\s*=\s*"([^"]*)"').Groups[1].Value
    $text = $events + "`n" + $prerequisites
    $tokens = @($eventType)
    $key = "$provider|$eventType"
    if ($aliases.ContainsKey($key)) { $tokens += $aliases[$key] }
    foreach ($token in ($tokens | Select-Object -Unique)) {
        if ($token -match '^\d{1,2}$') { continue }
        $pattern = if ($token -match '^\d+$') { '(?<!\d)' + [regex]::Escape($token) + '(?!\d)' } else { '(?<![A-Za-z0-9_])' + [regex]::Escape($token) + '(?![A-Za-z0-9_])' }
        if ($text -cmatch $pattern) { return $true }
    }
    return $false
}

$lines = Get-Content -LiteralPath $masterPath
$inMatrix = $false
$changed = $false
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -eq '## Atomic event matrix') { $inMatrix = $true; continue }
    if ($inMatrix -and $lines[$i] -match '^## ') { $inMatrix = $false }
    if (-not $inMatrix -or $lines[$i] -notmatch '^\|') { continue }
    $cells = $lines[$i].Split('|')
    if ($cells.Count -lt 11 -or $cells[1].Trim() -in @('Provider / product', '---')) { continue }
    $provider = $cells[1].Trim()
    $eventType = $cells[3].Trim()
    $existingToolIds = @($rules.Keys | Sort-Object)
    $entries = @()
    foreach ($toolId in $existingToolIds) {
        if (-not $rules.ContainsKey($toolId)) { continue }
        $dependent = @($rules[$toolId] | Where-Object { Test-RuleDependency $_.Text $provider $eventType })
        if ($dependent.Count -eq 0) { continue }
        $parts = @()
        foreach ($severity in @('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')) {
            $count = @($dependent | Where-Object Severity -eq $severity).Count
            if ($count -gt 0) { $parts += "$count $($severity.Substring(0,1))$($severity.Substring(1).ToLowerInvariant())" }
        }
        $display = if ($toolNames.ContainsKey($toolId)) { $toolNames[$toolId] } else { $toolId }
        $entries += "[$display ($($parts -join ', '))](./$toolId.md)"
    }
    $newValue = if ($entries.Count) { $entries -join ', ' } else { 'None' }
    if ($cells[8].Trim() -cne $newValue) {
        $cells[8] = " $newValue "
        $lines[$i] = $cells -join '|'
        $changed = $true
    }
}

if ($Check) {
    if ($changed) { throw 'telemetry/MASTER.md rule dependency counts are stale; run scripts/update-master-telemetry-rule-counts.ps1' }
    Write-Host 'Master telemetry rule dependency counts are current.'
} else {
    [IO.File]::WriteAllLines($masterPath, $lines, (New-Object Text.UTF8Encoding($false)))
    Write-Host 'Updated master telemetry rule dependency counts.'
}
