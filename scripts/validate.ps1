$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$required = @('registry', 'reports', 'detections', 'reviews', 'coverage', 'telemetry', 'sources', 'runs', 'state', 'templates', 'manifests', 'dependencies', 'summaries', 'schemas', 'context', 'public-rules')
$errors = [System.Collections.Generic.List[string]]::new()

foreach ($directory in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $repoRoot $directory) -PathType Container)) {
        $errors.Add("Missing required directory: $directory")
    }
}

$forbiddenExtensions = @('.exe', '.dll', '.sys', '.scr', '.com', '.msi', '.ps1xml', '.jar', '.apk', '.bin', '.elf')
Get-ChildItem -LiteralPath $repoRoot -Recurse -File -Force |
    Where-Object {
        $_.FullName -notlike "*$([IO.Path]::DirectorySeparatorChar).git$([IO.Path]::DirectorySeparatorChar)*" -and
        $_.FullName -notlike "*$([IO.Path]::DirectorySeparatorChar)public-rules$([IO.Path]::DirectorySeparatorChar).cache$([IO.Path]::DirectorySeparatorChar)*"
    } |
    ForEach-Object {
        if ($forbiddenExtensions -contains $_.Extension.ToLowerInvariant()) {
            $errors.Add("Forbidden binary/sample artifact: $($_.FullName)")
        }
        if ($_.Extension -ieq '.cart') {
            $quarantineRoot = Join-Path $repoRoot 'samples-quarantine'
            if (-not $_.FullName.StartsWith($quarantineRoot, [StringComparison]::OrdinalIgnoreCase)) {
                $errors.Add(".cart must remain under samples-quarantine: $($_.FullName)")
            }
        }
    }

$registryPath = Join-Path $repoRoot 'registry/tools.yml'
if (-not (Test-Path -LiteralPath $registryPath -PathType Leaf)) {
    $errors.Add('Missing registry/tools.yml')
} else {
    $registryText = Get-Content -Raw -LiteralPath $registryPath
    foreach ($field in @('schema_version:', 'tools:', 'status:', 'source_code:', 'evidence:')) {
        if ($registryText -notmatch [regex]::Escape($field)) {
            $errors.Add("Registry missing required field marker: $field")
        }
    }
    $toolBlocks = [regex]::Matches($registryText, '(?ms)^  - id:\s*(\S+).*?(?=^  - id:|\z)')
    foreach ($toolBlock in $toolBlocks) {
        $toolId = $toolBlock.Groups[1].Value
        if ($toolBlock.Value -match '(?m)^\s+category:\s*adversary-emulation\s*$' -and
            $toolBlock.Value -notmatch '(?m)^\s+status:\s*deprecated\s*$') {
            $errors.Add("BAS/adversary-emulation entry must be deprecated as out of scope: $toolId")
        }
        if ($toolBlock.Value -match '(?m)^\s+status:\s*analyzed\s*$') {
            $coveragePath = Join-Path $repoRoot "coverage/$toolId.yml"
            if (-not (Test-Path -LiteralPath $coveragePath -PathType Leaf)) {
                $errors.Add("Analyzed tool requires a coverage ledger: $coveragePath")
                continue
            }
            $coverageText = Get-Content -Raw -LiteralPath $coveragePath
            foreach ($completionMarker in @('inventory_complete: true', 'unassessed: 0', 'comprehensive_for_revision: true')) {
                if ($coverageText -notmatch [regex]::Escape($completionMarker)) {
                    $errors.Add("Analyzed tool '$toolId' is not comprehensively complete; missing '$completionMarker' in $coveragePath")
                }
            }
            $telemetryPath = Join-Path $repoRoot "telemetry/$toolId.md"
            if (-not (Test-Path -LiteralPath $telemetryPath -PathType Leaf)) {
                $errors.Add("Analyzed tool requires consolidated telemetry requirements: $telemetryPath")
            }
        }
    }
}

$detectionsRoot = Join-Path $repoRoot 'detections'
if (Test-Path -LiteralPath $detectionsRoot -PathType Container) {
    $formatDirectories = @('yaral', 'spl', 'kql', 'sql', 'eql', 'sigma')
    Get-ChildItem -LiteralPath $detectionsRoot -Directory | ForEach-Object {
        $toolDirectory = $_.FullName
        foreach ($formatDirectory in $formatDirectories) {
            if (-not (Test-Path -LiteralPath (Join-Path $toolDirectory $formatDirectory) -PathType Container)) {
                $errors.Add("Detection tool directory requires format subdirectory '$formatDirectory': $toolDirectory")
            }
        }
    }
    Get-ChildItem -LiteralPath $detectionsRoot -Recurse -File -Force |
        Where-Object { $_.Name -ne '.gitkeep' } |
        ForEach-Object {
            $formatName = $_.Directory.Name
            if ($formatName -ne 'yaral') {
                $expectedExtensions = @{ spl = '.spl'; kql = '.kql'; sql = '.sql'; eql = '.eql'; sigma = @('.yml', '.yaml') }
                if (-not $expectedExtensions.ContainsKey($formatName)) {
                    $errors.Add("Detection file is outside a recognized format directory: $($_.FullName)")
                } else {
                    $expected = @($expectedExtensions[$formatName])
                    if ($expected -notcontains $_.Extension.ToLowerInvariant()) {
                        $errors.Add("Detection translation in '$formatName' has an invalid extension: $($_.FullName)")
                    }
                    $canonicalPath = Join-Path $_.Directory.Parent.FullName "yaral/$($_.BaseName).yaral"
                    if (-not (Test-Path -LiteralPath $canonicalPath -PathType Leaf)) {
                        $errors.Add("Secondary translation has no same-named canonical YARA-L rule: $($_.FullName)")
                    }
                    $translationText = Get-Content -Raw -LiteralPath $_.FullName
                    foreach ($translationMarker in @('source_yaral', 'translation_status', 'fidelity')) {
                        if ($translationText -notmatch [regex]::Escape($translationMarker)) {
                            $errors.Add("Detection translation missing required marker '$translationMarker': $($_.FullName)")
                        }
                    }
                }
            } elseif ($_.Extension -ine '.yaral') {
                $errors.Add("Canonical detections must use YARA-L .yaral files: $($_.FullName)")
            } else {
                $ruleText = Get-Content -Raw -LiteralPath $_.FullName
                if ($ruleText -match '(?i)server[_ -]control[_ -]plane|authorized\s+(?:c2|sliver|havoc|cobalt strike)\s+server|teamserver\s+audit') {
                    $errors.Add("Canonical detection violates victim-host scope with server/operator control-plane logic: $($_.FullName)")
                }
                $ruleDeclarations = [regex]::Matches($ruleText, '(?m)^rule\s+([A-Za-z0-9_]+)\s*\{')
                if ($ruleDeclarations.Count -ne 1) {
                    $errors.Add("Each YARA-L file must contain exactly one rule; found $($ruleDeclarations.Count): $($_.FullName)")
                } elseif ($_.BaseName -cne $ruleDeclarations[0].Groups[1].Value) {
                    $errors.Add("YARA-L filename must exactly match its rule name '$($ruleDeclarations[0].Groups[1].Value).yaral': $($_.FullName)")
                }
                foreach ($marker in @('rule ', 'meta:', 'status = "experimental"', 'events:', 'condition:', 'procedure_ids', 'log_source_prerequisites', 'false_positives', 'severity_rationale', 'validation_status', 'review_status', 'review_reference')) {
                    if ($ruleText -notmatch [regex]::Escape($marker)) {
                        $errors.Add("YARA-L rule missing required marker '$marker': $($_.FullName)")
                    }
                }
                $toolName = $_.Directory.Parent.Name
                $reviewPath = Join-Path $repoRoot "reviews/$toolName/detection-review.md"
                if (-not (Test-Path -LiteralPath $reviewPath -PathType Leaf)) {
                    $errors.Add("YARA-L rules require a per-tool detection review: $reviewPath")
                } else {
                    $reviewText = Get-Content -Raw -LiteralPath $reviewPath
                    foreach ($reviewMarker in @('## Overall assessment', '## Findings', 'Assumption challenged:', 'Gap or failure mode:', 'Resolution:', '## Required follow-up')) {
                        if ($reviewText -notmatch [regex]::Escape($reviewMarker)) {
                            $errors.Add("Detection review missing required marker '$reviewMarker': $reviewPath")
                        }
                    }
                    if ($reviewText -match 'Severity:\s*`?blocker`?' -and $reviewText -notmatch 'Resolution:\s*`?(fixed|compensating_signal)`?') {
                        $errors.Add("Detection review contains an unresolved blocker: $reviewPath")
                    }
                }
            }
        }
}

$definedRuleNames = @{}
Get-ChildItem -LiteralPath $detectionsRoot -Recurse -Filter '*.yaral' -File | ForEach-Object {
    Select-String -LiteralPath $_.FullName -Pattern '^rule\s+([A-Za-z0-9_]+)' | ForEach-Object {
        $ruleName = $_.Matches[0].Groups[1].Value
        if ($definedRuleNames.ContainsKey($ruleName)) {
            $errors.Add("Duplicate YARA-L rule name '$ruleName': $($definedRuleNames[$ruleName]) and $($_.Path)")
        } else {
            $definedRuleNames[$ruleName] = $_.Path
        }
    }
}

$coverageRoot = Join-Path $repoRoot 'coverage'
Get-ChildItem -LiteralPath $coverageRoot -Filter '*.yml' -File | ForEach-Object {
    $currentCoveragePath = $_.FullName
    $coverageText = Get-Content -Raw -LiteralPath $_.FullName
    [regex]::Matches($coverageText, 'detection_rules:\s*\[([^\]]*)\]') | ForEach-Object {
        $_.Groups[1].Value.Split(',') | ForEach-Object {
            $referencedRule = $_.Trim()
            if ($referencedRule -and -not $definedRuleNames.ContainsKey($referencedRule)) {
                $errors.Add("Coverage ledger references undefined YARA-L rule '$referencedRule': $currentCoveragePath")
            }
        }
    }
}

$definedRuleNames.GetEnumerator() | ForEach-Object {
    $ruleName = $_.Key
    $rulePath = $_.Value
    $toolId = Split-Path -Leaf (Split-Path -Parent (Split-Path -Parent $rulePath))
    $telemetryPath = Join-Path $repoRoot "telemetry/$toolId.md"
    if (-not (Test-Path -LiteralPath $telemetryPath -PathType Leaf)) {
        $errors.Add("YARA-L rule has no tool telemetry requirements file: $ruleName -> $telemetryPath")
    } else {
        $telemetryText = Get-Content -Raw -LiteralPath $telemetryPath
        $quotedRuleName = [char]96 + $ruleName + [char]96
        if ($telemetryText -notmatch [regex]::Escape($quotedRuleName)) {
            $errors.Add("Telemetry requirements do not account for YARA-L rule '$ruleName': $telemetryPath")
        }
        foreach ($telemetryMarker in @('## Consolidated collection plan', '## Rule-by-rule requirements', 'Provider / product', 'Required fields', 'Enablement / configuration', 'Known gaps')) {
            if ($telemetryText -notmatch [regex]::Escape($telemetryMarker)) {
                $errors.Add("Telemetry requirements missing marker '$telemetryMarker': $telemetryPath")
            }
        }
    }
}

$translationFormats = @{
    spl = '.spl'
    kql = '.kql'
    sql = '.sql'
    eql = '.eql'
    sigma = '.yml'
}
Get-ChildItem -LiteralPath $detectionsRoot -Directory | ForEach-Object {
    $toolDirectory = $_
    $canonicalDirectory = Join-Path $toolDirectory.FullName 'yaral'
    Get-ChildItem -LiteralPath $canonicalDirectory -Filter '*.yaral' -File | ForEach-Object {
        $canonicalRule = $_
        foreach ($format in $translationFormats.Keys) {
            $translationPath = Join-Path $toolDirectory.FullName "$format/$($canonicalRule.BaseName)$($translationFormats[$format])"
            if (-not (Test-Path -LiteralPath $translationPath -PathType Leaf)) {
                $errors.Add("Canonical YARA-L rule is missing its '$format' translation: $($canonicalRule.FullName)")
            }
        }
    }
    $translationReviewPath = Join-Path $repoRoot "reviews/$($toolDirectory.Name)/translation-review.md"
    if (-not (Test-Path -LiteralPath $translationReviewPath -PathType Leaf)) {
        $errors.Add("Translated tool requires a translation review: $translationReviewPath")
    }
}

$masterTelemetryPath = Join-Path $repoRoot 'telemetry/MASTER.md'
if (-not (Test-Path -LiteralPath $masterTelemetryPath -PathType Leaf)) {
    $errors.Add("Missing master telemetry catalogue: $masterTelemetryPath")
} else {
    $masterTelemetryText = Get-Content -Raw -LiteralPath $masterTelemetryPath
    foreach ($masterMarker in @('## Atomic event matrix', '## Tool coverage index', 'Event ID / type', 'Supported tools', 'Detailed requirements')) {
        if ($masterTelemetryText -notmatch [regex]::Escape($masterMarker)) {
            $errors.Add("Master telemetry catalogue missing marker '$masterMarker': $masterTelemetryPath")
        }
    }
    $toolBlocks = [regex]::Matches($registryText, '(?ms)^  - id:\s*(\S+).*?(?=^  - id:|\z)')
    foreach ($toolBlock in $toolBlocks) {
        $toolId = $toolBlock.Groups[1].Value
        if ($toolBlock.Value -match '(?m)^\s+status:\s*analyzed\s*$') {
            $toolLinkTarget = "](./$toolId.md)"
            if ($masterTelemetryText -notmatch [regex]::Escape($toolLinkTarget)) {
                $errors.Add("Analyzed tool '$toolId' is missing from master telemetry catalogue: $masterTelemetryPath")
            }
        }
    }
}

& (Join-Path $repoRoot 'scripts/update-master-telemetry-rule-counts.ps1') -Check

foreach ($schemaProfile in @('chronicle-udm.yml', 'splunk-cim.yml', 'sentinel-asim.yml', 'normalized-sql.yml', 'elastic-ecs.yml', 'sigma.yml')) {
    $schemaPath = Join-Path $repoRoot "schemas/$schemaProfile"
    if (-not (Test-Path -LiteralPath $schemaPath -PathType Leaf)) {
        $errors.Add("Missing backend schema profile: $schemaPath")
    }
}

Get-ChildItem -LiteralPath (Join-Path $repoRoot 'manifests') -Filter '*.yml' -File | ForEach-Object {
    $lineCount = @(Get-Content -LiteralPath $_.FullName).Count
    if ($lineCount -gt 300) { $errors.Add("Tool manifest exceeds 300-line context budget ($lineCount): $($_.FullName)") }
}
Get-ChildItem -LiteralPath (Join-Path $repoRoot 'dependencies') -Recurse -Filter '*.yml' -File | ForEach-Object {
    $lineCount = @(Get-Content -LiteralPath $_.FullName).Count
    if ($lineCount -gt 100) { $errors.Add("Rule dependency record exceeds 100-line context budget ($lineCount): $($_.FullName)") }
}
Get-ChildItem -LiteralPath (Join-Path $repoRoot 'summaries') -Filter '*.md' -File | ForEach-Object {
    $toolId = $_.BaseName
    $coveragePath = Join-Path $repoRoot "coverage/$toolId.yml"
    $procedureCount = if (Test-Path -LiteralPath $coveragePath) { [regex]::Matches((Get-Content -Raw -LiteralPath $coveragePath), '(?m)^\s*-\s*\{\s*id:').Count } else { 0 }
    $budget = 40 + (20 * $procedureCount)
    $lineCount = @(Get-Content -LiteralPath $_.FullName).Count
    if ($lineCount -gt $budget) { $errors.Add("Tool summary exceeds context budget ($lineCount > $budget): $($_.FullName)") }
}

& (Join-Path $repoRoot 'scripts/update-context-index.ps1') -Check

$knowledgeFiles = @(
    'knowledge/README.md',
    'knowledge/config.json',
    'tools/knowledge/__init__.py',
    'tools/knowledge/store.py',
    'tools/knowledge/cli.py',
    'tests/test_knowledge_retrieval.py'
)
foreach ($knowledgeFile in $knowledgeFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $repoRoot $knowledgeFile) -PathType Leaf)) {
        $errors.Add("Missing knowledge retrieval artifact: $knowledgeFile")
    }
}
$dashboardFiles = @(
    'dashboard/catalog.py',
    'dashboard/presenters.py',
    'dashboard/workspace.py',
    'dashboard/server.py',
    'dashboard/static/index.html',
    'dashboard/static/app.css',
    'dashboard/static/theme.css',
    'dashboard/static/app.js',
    'dashboard/tests/test_catalog.py',
    'dashboard/tests/test_workspace.py',
    'dashboard/README.md',
    'dashboard/requirements.txt',
    'scripts/start-dashboard.ps1'
)
foreach ($dashboardFile in $dashboardFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $repoRoot $dashboardFile) -PathType Leaf)) {
        $errors.Add("Missing dashboard artifact: $dashboardFile")
    }
}
$changelogPath = Join-Path $repoRoot 'CHANGELOG.md'
if (-not (Test-Path -LiteralPath $changelogPath -PathType Leaf)) {
    $errors.Add('Missing agent capability changelog: CHANGELOG.md')
} else {
    $changelogText = Get-Content -Raw -LiteralPath $changelogPath
    foreach ($marker in @('# Changelog', '## Unreleased', '## Current feature inventory', '### Added', '### Changed', '### Security')) {
        if ($changelogText -notmatch [regex]::Escape($marker)) {
            $errors.Add("Agent changelog missing marker '$marker': CHANGELOG.md")
        }
    }
}
$knowledgeConfigPath = Join-Path $repoRoot 'knowledge/config.json'
if (Test-Path -LiteralPath $knowledgeConfigPath -PathType Leaf) {
    try {
        $knowledgeConfig = Get-Content -Raw -LiteralPath $knowledgeConfigPath | ConvertFrom-Json
        if ($knowledgeConfig.schema_version -ne 1) { $errors.Add('Unsupported knowledge configuration schema') }
        if ($knowledgeConfig.embedding.adapter -ne 'none') { $errors.Add('Unvalidated knowledge embedding adapter configured') }
        if ($knowledgeConfig.ranking.max_chunks_per_source -lt 1) { $errors.Add('Knowledge result diversification must permit at least one chunk per source') }
        foreach ($source in $knowledgeConfig.sources) {
            if (-not $source.path) { $errors.Add('Knowledge source missing path') }
            if (-not $source.domain -or -not $source.type -or -not $source.authority) {
                $errors.Add("Knowledge source '$($source.path)' lacks domain, type, or authority")
            }
        }
    } catch { $errors.Add("Invalid knowledge configuration JSON: $($_.Exception.Message)") }
}

# A completed dated run must prove that indexed retrieval preceded broad repository work.
# Query text remains in the ignored private telemetry database; the run log stores only
# the receipt and attributed sources needed to audit workflow compliance.
Get-ChildItem -LiteralPath (Join-Path $repoRoot 'runs') -Filter '????-??-??.md' -File | ForEach-Object {
    $runText = Get-Content -Raw -LiteralPath $_.FullName
    foreach ($marker in @('## Knowledge retrieval evidence', 'Receipt ID:', 'Timestamp:', 'Purpose:', 'Result count:', 'Sources used:')) {
        if ($runText -notmatch [regex]::Escape($marker)) {
            $errors.Add("Completed run log missing knowledge-first evidence marker '$marker': $($_.FullName)")
        }
    }
    foreach ($marker in @('Action journal:', 'runs/actions/')) {
        if ($runText -notmatch [regex]::Escape($marker)) {
            $errors.Add("Completed run log missing action-journal marker '$marker': $($_.FullName)")
        }
    }
}

$actionRoot = Join-Path $repoRoot 'runs/actions'
if (-not (Test-Path -LiteralPath $actionRoot -PathType Container)) {
    $errors.Add('Missing per-run action journal directory: runs/actions')
} else {
    Get-ChildItem -LiteralPath $actionRoot -Filter '*.jsonl' -File | ForEach-Object {
        $expectedSequence = 1
        Get-Content -LiteralPath $_.FullName | Where-Object { $_.Trim() } | ForEach-Object {
            try {
                $event = $_ | ConvertFrom-Json
                foreach ($field in @('timestamp', 'sequence', 'run_id', 'phase', 'action', 'target', 'outcome', 'details')) {
                    if (-not $event.PSObject.Properties.Name.Contains($field)) {
                        $errors.Add("Action journal event missing '$field': $($_.FullName)")
                    }
                }
                if ($event.timestamp -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?\+00:00$') {
                    $errors.Add("Action journal timestamp is not UTC ISO-8601: $($_.FullName)")
                }
                if ($event.sequence -ne $expectedSequence) {
                    $errors.Add("Action journal sequence is not monotonic at $expectedSequence`: $($_.FullName)")
                }
                if (@('started', 'succeeded', 'failed', 'blocked', 'skipped') -notcontains $event.outcome) {
                    $errors.Add("Action journal has invalid outcome '$($event.outcome)': $($_.FullName)")
                }
            } catch {
                $errors.Add("Invalid action journal JSON: $($_.FullName): $($_.Exception.Message)")
            }
            $expectedSequence++
        }
        if ($expectedSequence -eq 1) { $errors.Add("Empty action journal: $($_.FullName)") }
    }
}

$publicCatalogPath = Join-Path $repoRoot 'public-rules/catalog.json'
if (-not (Test-Path -LiteralPath $publicCatalogPath -PathType Leaf)) {
    $errors.Add("Missing public-rule source catalog: $publicCatalogPath")
} else {
    try {
        $publicCatalog = Get-Content -Raw -LiteralPath $publicCatalogPath | ConvertFrom-Json
        if ($publicCatalog.schema_version -ne 1) { $errors.Add('Unsupported public-rule catalog schema') }
        $sourceIds = @{}
        foreach ($source in $publicCatalog.sources) {
            if ($source.id -notmatch '^[a-z0-9][a-z0-9-]+$') { $errors.Add("Invalid public-rule source id: $($source.id)") }
            if ($sourceIds.ContainsKey($source.id)) { $errors.Add("Duplicate public-rule source id: $($source.id)") } else { $sourceIds[$source.id] = $true }
            foreach ($field in @('repository', 'default_branch', 'formats', 'include_paths', 'extensions', 'license', 'license_url')) {
                if (-not $source.PSObject.Properties.Name.Contains($field)) { $errors.Add("Public-rule source '$($source.id)' missing '$field'") }
            }
        }
    } catch { $errors.Add("Invalid public-rule catalog JSON: $($_.Exception.Message)") }
}

$comparisonRoot = Join-Path $repoRoot 'public-rules/comparisons'
Get-ChildItem -LiteralPath $comparisonRoot -Recurse -Filter '*.md' -File | Where-Object { $_.Name -ne 'INDEX.md' } | ForEach-Object {
    $comparisonText = Get-Content -Raw -LiteralPath $_.FullName
    foreach ($marker in @('## Identity and independence gate', 'Internal SHA-256:', 'Internal review completed before public comparison:', '## Procedure and detection-branch matrix', 'Primary signal and strength', '## Missing detection branches', '## Detection edge cases and blind spots', '## Signal-quality assessment', '## Public-rule weaknesses', '## Internal-rule weaknesses', '## Decision trail', '## Unmatched scope', '## Proposed YARA-L improvement', 'Validation status: `unvalidated_proposal`', '```yaral', 'rule ')) {
        if ($comparisonText -notmatch [regex]::Escape($marker)) { $errors.Add("Public-rule comparison missing marker '$marker': $($_.FullName)") }
    }
    if ($comparisonText -notmatch '(?m)^- Change type: `(?:patch|compensating_rule|split|rewrite|new_rule)`\s*$') {
        $errors.Add("Public-rule comparison requires an allowed YARA-L change type: $($_.FullName)")
    }
    $proposalBlock = [regex]::Match($comparisonText, '(?ms)```yaral\s+(.*?)\s+```')
    if (-not $proposalBlock.Success) {
        $errors.Add("Public-rule comparison requires a YARA-L proposal code block: $($_.FullName)")
    } else {
        if ($proposalBlock.Groups[1].Value -match '(?i)\b(?:procedure_signal|security_effect|placeholder|todo|tbd)\b|<[^>]+>') {
            $errors.Add("Public-rule YARA-L proposal contains placeholder detection logic: $($_.FullName)")
        }
        foreach ($proposalMarker in @('rule ', 'events:', 'condition:')) {
            if ($proposalBlock.Groups[1].Value -notmatch [regex]::Escape($proposalMarker)) {
                $errors.Add("Public-rule YARA-L proposal missing '$proposalMarker': $($_.FullName)")
            }
        }
    }
}

if ($errors.Count -gt 0) {
    $errors | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Host 'Detection research repository validation passed.'
