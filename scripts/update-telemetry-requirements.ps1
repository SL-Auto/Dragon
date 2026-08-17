param(
    [string[]]$Tool = @('rubeus', 'mimikatz', 'sliver', 'impacket')
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$telemetryRoot = Join-Path $repoRoot 'telemetry'
New-Item -ItemType Directory -Path $telemetryRoot -Force | Out-Null

$plans = @{
    rubeus = @(
        @('TEL-001','Windows domain controllers / Security log','4768, 4769, 4770','account, source IP/host, service/SPN, result, ticket options, pre-auth and encryption types','Enable Kerberos Authentication Service and Service Ticket Operations success/failure auditing; centralize every DC','At least 24 hours online for long absence correlations; preserve event time','Parser fields vary; missing DCs invalidate absence logic','PROC-001â€“005, PROC-008â€“009, PROC-012'),
        @('TEL-002','EDR API / endpoint sensor','LSA authentication-package calls and process lineage','caller image/entity, user, host, API name, Kerberos message type, target LUID','Enable vendor API/credential-access telemetry and retain raw events','Correlate by host, LUID and process entity for at least 30 minutes','Not available in standard Windows logs; vendor mappings differ','PROC-006â€“007'),
        @('TEL-003','EDR, Sysmon, firewall and proxy','process launch, network connection, HTTP','process entity/path/signer, destination DC/proxy, port, HTTP Content-Type','Enable process-attributed network and HTTP header telemetry','Retain 24 hours; correlate process to DC/proxy events','Perimeter logs may lack process attribution; encrypted proxy inspection may be unavailable','PROC-001â€“005, PROC-013'),
        @('TEL-004','EDR file telemetry','file read/create','process entity, user, full path, operation, signer','Enable file reads and creates for ticket/artifact locations','Retain at least 7 days','Memory-only operations and renamed artifacts are missed','PROC-008â€“010, PROC-013'),
        @('TEL-005','Resource servers and identity analytics','Kerberos service use and PAC/identity anomalies','user, source, service, target, auth method, PAC validation result','Collect resource-side authentication and PAC validation where supported','Retain at least 24 hours aligned with complete DC logs','Absence is unsafe when DC logs are incomplete; PAC fields are product-specific','PROC-008â€“009')
    )
    mimikatz = @(
        @('TEL-001','Sysmon and EDR process telemetry','process launch/open/injection/module/driver','source and target process entities, paths, signer, user, access mask, operation, parent','Enable Process Access, tamper/injection, driver and module telemetry','Retain 7 days and preserve stable process entity IDs','Standard logs do not expose memory contents; vendor event types differ','P02â€“P09, P13, P22, P27â€“P28, P32, P40, P43â€“P45'),
        @('TEL-002','Windows Security and domain controllers','4624, 4656, 4662, 4663, 472x, 5136 and replication events','subject/logon ID, source host/IP, object/path, access rights/GUID, target identity','Enable Logon, Object Access, Directory Service Access/Changes and account-management auditing with scoped SACLs','Retain 30 days for identity baselining','SACLs and localization affect visibility; directory events can be high volume','P12, P14â€“P16, P29'),
        @('TEL-003','EDR file and registry telemetry','sensitive file/registry read, create, delete and mutation','process entity, user, target path/key/value, operation, result','Enable read telemetry for credential/key stores and protected registry paths','Retain 7â€“30 days according to store sensitivity','Many sensors collect writes but not reads; offline copies may evade live registry logs','P12, P18â€“P21, P23â€“P25, P33, P37, P41, P46'),
        @('TEL-004','Service, driver, print and event-log providers','7045, 4697, 1102, service/driver/print changes','actor, host, service/driver/module, image path, signer, target log/provider','Forward System, Security, PrintService and driver/module telemetry','Retain 30 days','Provider enablement and event schemas vary','P06, P26, P36, P43â€“P45'),
        @('TEL-005','EDR device, firmware, clipboard and named-pipe telemetry','device/firmware access, clipboard read, pipe/RPC operations','process entity, user, device or pipe, operation, peer, result','Enable advanced device, clipboard, firmware and IPC telemetry where supported','Retain 7 days','Mostly vendor-specific and sometimes unavailable','P34â€“P35, P38â€“P39, P42â€“P43'),
        @('TEL-006','Network, DNS, LDAP and RPC sensors','network connection, LDAP query, RPC interface','process/source, destination, protocol/interface, LDAP filter, account','Collect east-west DNS/LDAP/RPC and process-attributed network telemetry','Retain 14 days','Encryption and dynamic RPC ports reduce visibility','P14â€“P16, P30, P35, P38')
    )
    sliver = @(
        @('TEL-001','EDR process and network telemetry','process launch/termination, connect/listen','stable process entity/PID, parent, image, signer, user, destination, port, direction','Enable process-attributed connect and listen telemetry on all supported platforms','Retain at least 7 days; correlate by stable process entity','PID reuse and missing process attribution weaken joins','PROC-001â€“005, PROC-010, PROC-021â€“022, PROC-026'),
        @('TEL-002','DNS, proxy, TLS and firewall','DNS, HTTP/S, TLS and UDP flows','source process/host, query, destination, SNI, certificate, method/URI, bytes, timing','Centralize endpoint and network egress metadata','Retain 14 days for prevalence and recurrence baselines','Encrypted/custom transports and destination churn reduce specificity','PROC-002â€“005, PROC-021'),
        @('TEL-003','EDR file, registry and memory telemetry','file read/write/delete, registry change, process access/injection/memory load','process entity, target, operation, path/key, signer, user','Enable file lifecycle, registry, process-tamper and memory telemetry','Retain 7 days','Memory-only and vendor-specific operations may be unavailable','PROC-007â€“012, PROC-015, PROC-018, PROC-026'),
        @('TEL-004','Windows/Linux/macOS identity and execution logs','logon, privilege, service, task, SSH and command execution','account, source, host, parent/child, service/task/action, result','Enable platform authentication, process, service/task and SSH auditing','Retain 30 days for administrative baselines','Cross-platform schemas and remote causality differ','PROC-010, PROC-016â€“020'),
        @('TEL-005','EDR collection sensors','screen capture and collection events','process entity, user/session, collection type, bytes and subsequent egress','Enable vendor screen/collection telemetry if available','Retain 7 days','Standard OS logs often do not expose capture; rule must be disabled without verified mapping','PROC-013â€“014'),
    )
    impacket = @(
        @('TEL-001','Windows Security/System and EDR','4624, 4672, 4688, 4697, 5140, 5145, 7045 and process/file/network events','source IP, account/logon ID, host, share/path, service image, process lineage, signer','Enable Logon, Process Creation, Detailed File Share and service auditing; collect EDR process/file/network','Retain 30 days; correlate source and target by account/logon/time','High-volume management activity overlaps and cross-host IDs may not join','IMP-01â€“05, IMP-07â€“08, IMP-13â€“16, IMP-18, IMP-22'),
        @('TEL-002','Task Scheduler and WMI providers','TaskScheduler 100/106/141/200, Security 4698/4699, WMI Activity 5857â€“5861','task name/action, account, host, client process, namespace, operation, child process','Enable and forward TaskScheduler and WMI Activity Operational logs','Retain 14 days','IDs/fields vary by OS; outputless execution lacks SMB artifacts','IMP-04â€“06'),
        @('TEL-003','Domain controllers and directory services','4768, 4769, 4662, 5136 and LDAP queries','source, account, object/GUID, attribute, filter, service, ticket options/result','Enable Kerberos and Directory Service Access/Changes with scoped SACLs','Retain 30 days','Encrypted LDAP and missing SACLs create gaps','IMP-09â€“11, IMP-13'),
        @('TEL-004','Network IDS/NDR, firewall and endpoint sockets','SMB, RPC/DCOM, LDAP, MSSQL, mail, raw socket, ICMP, capture/listener events','source/destination, port, protocol/interface, process, account, bytes and direction','Collect east-west protocol metadata and endpoint socket listen/connect telemetry','Retain 14 days','Encryption/dynamic RPC ports and missing process identity reduce attribution','IMP-02, IMP-05, IMP-08, IMP-15â€“19, IMP-21â€“22'),
        @('TEL-005','Application and service audit','MSSQL, Exchange/mail, Terminal Services and remote registry','authenticated principal, source, action/query, target object, result','Enable product-native audit and centralize service logs','Retain 30 days','Coverage differs by product; Exchange source remains blocked in this revision','IMP-14â€“18'),
        @('TEL-006','EDR sensitive-store and artifact telemetry','credential store/hive/database reads and local artifact conversion','process, user, target path/object, operation, result','Enable sensitive file/registry reads and artifact lifecycle telemetry','Retain 14 days','Offline parsing/conversion is not uniquely observable','IMP-12â€“14, IMP-20')
    )
}

function Get-MetaValue([string]$block, [string]$name) {
    $pattern = '(?m)^\s*' + [regex]::Escape($name) + '\s*=\s*"([^"]*)"'
    $match = [regex]::Match($block, $pattern)
    if ($match.Success) { return $match.Groups[1].Value }
    return ''
}

foreach ($toolId in $Tool) {
    $ruleFiles = Get-ChildItem -LiteralPath (Join-Path $repoRoot "detections/$toolId/yaral") -Filter '*.yaral' -File
    $rules = [System.Collections.Generic.List[object]]::new()
    foreach ($ruleFile in $ruleFiles) {
        $text = Get-Content -Raw -LiteralPath $ruleFile.FullName
        $matches = [regex]::Matches($text, '(?ms)^rule\s+([A-Za-z0-9_]+)\s*\{(.*?)(?=^rule\s+|\z)')
        foreach ($match in $matches) {
            $block = $match.Groups[2].Value
            $rules.Add([pscustomobject]@{
                Name = $match.Groups[1].Value
                Procedures = Get-MetaValue $block 'procedure_ids'
                Prerequisite = Get-MetaValue $block 'log_source_prerequisites'
                File = $ruleFile.Name
            })
        }
    }

    $registryText = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'registry/tools.yml')
    $toolBlock = [regex]::Match($registryText, "(?ms)^  - id:\s*$toolId\s*.*?(?=^  - id:|\z)").Value
    $revision = [regex]::Match($toolBlock, 'analyzed_revision:\s*([^\s}\r\n]+)').Groups[1].Value
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("# $toolId telemetry requirements")
    $lines.Add('')
    $lines.Add('## Scope')
    $lines.Add('')
    $lines.Add("- Tool revision: ``$revision``")
    $formattedFiles = ($ruleFiles.Name | ForEach-Object { '``' + $_ + '``' }) -join ', '
    $lines.Add("- Detection files: $formattedFiles")
    $lines.Add('- Generated/reviewed: 2026-08-15')
    $lines.Add('- Status: `complete_for_experimental_rules`')
    $lines.Add('')
    $lines.Add('## Consolidated collection plan')
    $lines.Add('')
    $lines.Add('| Capability ID | Provider / product | Events / IDs | Required fields | Enablement / configuration | Retention / correlation | Known gaps | Supports |')
    $lines.Add('| --- | --- | --- | --- | --- | --- | --- | --- |')
    foreach ($row in $plans[$toolId]) {
        $lines.Add('| ' + (($row | ForEach-Object { $_ -replace '\|','/' }) -join ' | ') + ' |')
    }
    $lines.Add('')
    $lines.Add('## Rule-by-rule requirements')
    $lines.Add('')
    $lines.Add('| YARA-L rule | Procedures | Capability IDs | Minimum viable telemetry | Optional enrichment | Failure mode if absent |')
    $lines.Add('| --- | --- | --- | --- | --- | --- |')
    foreach ($rule in ($rules | Sort-Object Name)) {
        $minimum = ($rule.Prerequisite -replace '\|','/').Trim()
        $lines.Add("| ``$($rule.Name)`` | $($rule.Procedures) | See consolidated plan by event/provider | $minimum | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |")
    }
    $lines.Add('')
    $lines.Add('## Deployment order')
    $lines.Add('')
    $lines.Add('1. Collect and validate the foundational identity, process and network sources before enabling correlations.')
    $lines.Add('2. Verify every parser field referenced by a rule using representative sanitized events.')
    $lines.Add('3. Enable high-confidence effect/sequence rules, then baseline cardinality and rarity rules.')
    $lines.Add('4. Enable vendor-specific EDR/API rules only where the required event mapping is confirmed.')
    $lines.Add('5. Review collection health continuously; missing sources must degrade coverage explicitly.')
    $lines.Add('')
    $lines.Add('## Validation checklist')
    $lines.Add('')
    $lines.Add('- [x] Every current YARA-L rule appears in the rule matrix.')
    $lines.Add('- [ ] Provider/parser mappings were verified in the target tenant.')
    $lines.Add('- [ ] Required fields are populated in representative events.')
    $lines.Add('- [ ] Retention supports every correlation window and absence check.')
    $lines.Add('- [ ] Missing-source behavior and compensating signals were tested.')
    $lines.Add('- [ ] Collection volume, privacy, and access controls were reviewed.')
    $lines.Add('')
    $lines.Add('## Unresolved telemetry gaps')
    $lines.Add('')
    $lines.Add('- Rules remain experimental until tenant-specific parser mappings and representative fixtures are validated.')
    $lines.Add('- Vendor-specific EDR events must not be assumed present; disable dependent rules when the mapping is unavailable.')
    $lines.Add('- Offline or memory-only procedures may have no direct event and require the compensating signals documented in the coverage ledger and detection review.')
    $lines.Add('')
    $outputPath = Join-Path $telemetryRoot "$toolId.md"
    Set-Content -LiteralPath $outputPath -Value $lines -Encoding utf8
    Write-Host "Updated $outputPath with $($rules.Count) rules."
}
