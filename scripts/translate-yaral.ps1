param(
    [string[]]$Tool,
    [string[]]$Rule,
    [ValidateSet('spl','kql','sql','eql','sigma')]
    [string[]]$Format = @('spl','kql','sql','eql','sigma')
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$detectionsRoot = Join-Path $repoRoot 'detections'

function Meta([string]$text, [string]$name) {
    $m = [regex]::Match($text, '(?m)^\s*' + [regex]::Escape($name) + '\s*=\s*"([^"]*)"')
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}

function SafeComment([string]$value) { return (($value -replace '[\r\n]+', ' ') -replace '\*/', '* /') }
function SqlQuote([string]$value) { return "'" + ($value -replace "'", "''") + "'" }
function YamlQuote([string]$value) { return '"' + (($value -replace '\\', '\\') -replace '"', '\"') + '"' }

$toolDirectories = Get-ChildItem -LiteralPath $detectionsRoot -Directory
if ($Tool) { $toolDirectories = $toolDirectories | Where-Object Name -in $Tool }

foreach ($toolDirectory in $toolDirectories) {
    $yaralDirectory = Join-Path $toolDirectory.FullName 'yaral'
    foreach ($targetFormat in @('spl','kql','sql','eql','sigma')) {
        if ($Format -contains $targetFormat) {
            New-Item -ItemType Directory -Force -Path (Join-Path $toolDirectory.FullName $targetFormat) | Out-Null
        }
    }
    $canonicalFiles = Get-ChildItem -LiteralPath $yaralDirectory -Filter '*.yaral' -File
    if ($Rule) { $canonicalFiles = $canonicalFiles | Where-Object BaseName -in $Rule }
    foreach ($yaralFile in $canonicalFiles) {
        $text = Get-Content -Raw -LiteralPath $yaralFile.FullName
        $ruleName = [regex]::Match($text, '(?m)^rule\s+([A-Za-z0-9_]+)').Groups[1].Value
        $description = Meta $text 'description'
        $severity = (Meta $text 'severity').ToLowerInvariant()
        $procedures = Meta $text 'procedure_ids'
        $prerequisites = Meta $text 'log_source_prerequisites'
        $falsePositives = Meta $text 'false_positives'
        $references = Meta $text 'references'
        $source = "detections/$($toolDirectory.Name)/yaral/$($yaralFile.Name)"

        $eventTypes = [System.Collections.Generic.List[string]]::new()
        [regex]::Matches($text, '(?m)metadata\.(?:product_event_type|event_type)\s*=\s*"([^"]+)"') | ForEach-Object { $eventTypes.Add($_.Groups[1].Value) }
        [regex]::Matches($text, '(?m)metadata\.(?:product_event_type|event_type)\s*=\s*/([^/]+)/') | ForEach-Object {
            ($_.Groups[1].Value -replace '[()]', '').Split('|') | ForEach-Object { if ($_ -match '^[A-Za-z0-9_ -]+$') { $eventTypes.Add($_) } }
        }
        [regex]::Matches($text, '(?m)re\.regex\(\$[A-Za-z0-9_]+\.metadata\.(?:product_event_type|event_type),\s*`([^`]+)`\)') | ForEach-Object {
            (($_.Groups[1].Value -replace '[\^$()]', '')).Split('|') | ForEach-Object { if ($_ -match '^[A-Za-z0-9_ -]+$') { $eventTypes.Add($_) } }
        }
        $eventTypes = @($eventTypes | Sort-Object -Unique)
        $hasCorrelation = $text -match '(?m)^\s*match:' -or ([regex]::Matches($text, '(?m)^\s*\$[A-Za-z0-9_]+\.metadata\.').Count -gt 1)
        $hasAggregation = $text -match '(?m)^\s*outcome:' -or $text -match 'count(?:_distinct)?\('
        $hasAbsence = $text -match '(?i)not\s+\$|!\$'
        $fidelity = if ($hasAbsence) { 'unsupported' } elseif ($hasCorrelation -or $hasAggregation) { 'partial' } else { 'partial' }
        $status = 'experimental_needs_backend_mapping_and_validation'
        $gaps = if ($hasAbsence) { 'Target draft does not safely reproduce canonical absence logic; implement only after confirming complete source coverage and time semantics.' } elseif ($hasCorrelation -or $hasAggregation) { 'Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.' } else { 'Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.' }
        $eventListSql = if ($eventTypes.Count) { ($eventTypes | ForEach-Object { SqlQuote $_ }) -join ', ' } else { "'*'" }
        $eventListDouble = if ($eventTypes.Count) { ($eventTypes | ForEach-Object { '"' + ($_ -replace '"','\"') + '"' }) -join ', ' } else { '"*"' }
        $eventListYaml = if ($eventTypes.Count) { '[' + (($eventTypes | ForEach-Object { YamlQuote $_ }) -join ', ') + ']' } else { '["*"]' }

        $common = @(
            "source_yaral: $source",
            "translation_status: $status",
            "fidelity: $fidelity",
            "rule_name: $ruleName",
            "severity: $severity",
            "procedure_ids: $procedures",
            "description: $(SafeComment $description)",
            "log_source_prerequisites: $(SafeComment $prerequisites)",
            "false_positives: $(SafeComment $falsePositives)",
            "references: $(SafeComment $references)",
            "assumptions_and_gaps: $gaps"
        )

        if ($Format -contains 'spl') {
        $spl = ($common + 'schema_profile: schemas/splunk-cim.yml' | ForEach-Object { '# ' + $_ }) + @(
            'index=<configured_index>',
            "| where in(coalesce('metadata.product_event_type','metadata.event_type'), $eventListDouble)",
            "| eval canonical_rule=`"$ruleName`"",
            "| stats count values('metadata.product_event_type') as observed_event_types by 'principal.hostname', 'principal.user.userid'",
            '| where count > 0'
        )
        [IO.File]::WriteAllLines((Join-Path $toolDirectory.FullName "spl/$ruleName.spl"), $spl, (New-Object Text.UTF8Encoding($false)))
        }

        if ($Format -contains 'kql') {
        $kql = ($common + 'schema_profile: schemas/sentinel-asim.yml' | ForEach-Object { '// ' + $_ }) + @(
            'NormalizedEvents',
            "| where ProductEventType in ($eventListDouble) or EventType in ($eventListDouble)",
            "| summarize EventCount=count(), ObservedEventTypes=make_set(ProductEventType) by Hostname, UserId",
            '| where EventCount > 0',
            "| extend CanonicalRule=`"$ruleName`""
        )
        [IO.File]::WriteAllLines((Join-Path $toolDirectory.FullName "kql/$ruleName.kql"), $kql, (New-Object Text.UTF8Encoding($false)))
        }

        if ($Format -contains 'sql') {
        $sql = ($common + 'schema_profile: schemas/normalized-sql.yml' | ForEach-Object { '-- ' + $_ }) + @(
            '-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).',
            'SELECT hostname, user_id, COUNT(*) AS event_count,',
            "       '$ruleName' AS canonical_rule",
            'FROM normalized_events',
            "WHERE product_event_type IN ($eventListSql) OR event_type IN ($eventListSql)",
            'GROUP BY hostname, user_id',
            'HAVING COUNT(*) > 0;'
        )
        [IO.File]::WriteAllLines((Join-Path $toolDirectory.FullName "sql/$ruleName.sql"), $sql, (New-Object Text.UTF8Encoding($false)))
        }

        if ($Format -contains 'eql') {
        $eql = ($common + 'schema_profile: schemas/elastic-ecs.yml' | ForEach-Object { '// ' + $_ }) + @(
            '// ECS assumption: event.code carries product IDs and event.action carries normalized event types.',
            "any where event.code in ($eventListDouble) or event.action in ($eventListDouble)"
        )
        [IO.File]::WriteAllLines((Join-Path $toolDirectory.FullName "eql/$ruleName.eql"), $eql, (New-Object Text.UTF8Encoding($false)))
        }

        if ($Format -contains 'sigma') {
        $sigma = @(
            "title: $(YamlQuote $description)",
            "name: $ruleName",
            "status: experimental",
            "description: $(YamlQuote $description)",
            "source_yaral: $(YamlQuote $source)",
            "translation_status: $status",
            "fidelity: $fidelity",
            'schema_profile: schemas/sigma.yml',
            "assumptions_and_gaps: $(YamlQuote $gaps)",
            'references:',
            "  - $(YamlQuote $references)",
            "procedure_ids: $(YamlQuote $procedures)",
            "log_source_prerequisites: $(YamlQuote $prerequisites)",
            'logsource:',
            '  category: generic',
            'detection:',
            '  selection_event_type:',
            "    event.code: $eventListYaml",
            '  condition: selection_event_type',
            'falsepositives:',
            "  - $(YamlQuote $falsePositives)",
            "level: $severity"
        )
        [IO.File]::WriteAllLines((Join-Path $toolDirectory.FullName "sigma/$ruleName.yml"), $sigma, (New-Object Text.UTF8Encoding($false)))
        }
    }
    Write-Host "Translated $(@($canonicalFiles).Count) canonical rules for $($toolDirectory.Name) into $($Format -join ', ')."
}
