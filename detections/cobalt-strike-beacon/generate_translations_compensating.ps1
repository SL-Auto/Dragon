$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$det = $PSScriptRoot

$items = @(
  @{n='cobalt_strike_credential_access_effect_compensating_signal';sev='high';p='CSB-028';desc='Correlates dangerous-rights LSASS process access with creation of a memory-dump artifact by the same process, narrowing the broad LSASS/store/replication effect rule to an ordered access-plus-artifact sequence.';lsp='Normalize EDR PROCESS_OPEN against lsass.exe with a granted-access/dangerous-rights enrichment field, plus FILE_CREATION for .dmp/.mdmp targets, joined on process PID within a 5-minute window.';fp='EDR/AV LSASS scanners, Procdump-based support workflows, Windows Error Reporting crash dumps, and forensic acquisition tools that also create .dmp files.';evts=@('PROCESS_OPEN','FILE_CREATION')},
  @{n='cobalt_strike_directory_discovery_compensating_signal';sev='medium';p='CSB-022';desc="Aggregates multi-class LDAP directory queries by user and host, independent of any single process, to surface discovery distributed across multiple short-lived processes in the same session.";lsp='Normalize LDAP_QUERY with client account, hostname, and object-class field, plus an allowlist enrichment identifying approved directory-scanning software.';fp='Identity governance, endpoint inventory, directory health, administration and vulnerability-assessment tooling that legitimately queries many object classes.';evts=@('LDAP_QUERY')},
  @{n='cobalt_strike_discovery_fanout_compensating_signal';sev='medium';p='CSB-021';desc="Aggregates attempted network connections by user and host over a wider window at a lower per-process threshold to surface slow or distributed port/network discovery that falls under the single-process fan-out rule's threshold.";lsp='Normalize process-attributed NETWORK_CONNECTION attempts with destination IP/port, account, hostname, and an allowlist enrichment identifying approved scanners.';fp='Vulnerability scanners, monitoring, software distribution, service discovery and network management tools not present in the approved-scanner enrichment.';evts=@('NETWORK_CONNECTION')},
  @{n='cobalt_strike_dns_process_context_compensating_signal';sev='medium';p='CSB-006';desc='Detects repeated process-attributed TXT/NULL-type DNS queries to domains flagged as rare by baseline enrichment, covering low-volume record-type-specific tunneling exchanges that the length/entropy-based base rule does not filter by record type.';lsp='Normalize DNS_QUERY with process, host, query name/type, and a domain-rarity baseline enrichment field.';fp='Mail-security appliances and anti-abuse services performing bulk legitimate TXT lookups against rare or newly observed domains; the rarity enrichment must be tenant-tuned before enabling.';evts=@('DNS_QUERY')},
  @{n='cobalt_strike_named_pipe_peer_activity_compensating_signal';sev='high';p='CSB-007';desc='Correlates a remote SMB connection to IPC$ with a subsequent rare local pipe connect on the same host, closing the ordered remote-peer branch that the standalone pipe-rarity base rule does not capture.';lsp='Normalize NETWORK_CONNECTION to TCP/445 with source/target hostname, plus PIPE_CONNECT with a pipe-rarity enrichment field, joined on source-to-target host within 5 minutes.';fp='Remote administration frameworks, backup/replication agents, and clustered service frameworks that legitimately combine SMB sessions with rare local pipes.';evts=@('NETWORK_CONNECTION','PIPE_CONNECT')},
  @{n='cobalt_strike_privileged_context_change_compensating_signal';sev='high';p='CSB-011';desc="Correlates SeDebugPrivilege enablement on a process with that same process subsequently opening a protected process (lsass.exe or winlogon.exe), closing the causal gap left by the base rule's standalone 4672/token-change signal.";lsp='Normalize TOKEN_PRIVILEGE_CHANGE with the enabled privilege name, and PROCESS_OPEN with target image path, joined on host and PID within 10 minutes.';fp='EDR, debuggers, backup/VSS tooling, and administrative diagnostic utilities that enable SeDebugPrivilege before inspecting system processes.';evts=@('TOKEN_PRIVILEGE_CHANGE','PROCESS_OPEN')},
  @{n='cobalt_strike_remote_service_sequence_compensating_signal';sev='high';p='CSB-030';desc="Correlates a staged file write to a remote target with a subsequent System 7045 service-install event on that same target whose service image path equals the staged path, tightening the base rule's looser source/account/host proximity join with an exact-path match.";lsp='Normalize FILE_WRITE to a remote target host with full path, and System 7045 on that target with the installed service image path, joined on source host, target host, and path within 10 minutes.';fp='Software distribution and endpoint-management tools that stage an installer to a share and then register it as a service using the identical path.';evts=@('FILE_WRITE','7045')},
  @{n='cobalt_strike_suspicious_process_lineage_or_memory_compensating_signal';sev='high';p='CSB-004,CSB-014,CSB-016';desc="Correlates a private executable-memory region without a backing file with a subsequent thread start whose start address falls in that private region, on the same process, providing execution evidence that the base rule's standalone memory-allocation signal cannot express.";lsp='Normalize EXECUTABLE_MEMORY with private/backing-file attributes and THREAD_START with start-address-in-region and expected-JIT-host enrichment, joined on host and PID within 5 minutes.';fp='JIT runtimes (browsers, .NET, JVM), application virtualization, and approved dynamic-code frameworks not reflected in the JIT-host enrichment.';evts=@('EXECUTABLE_MEMORY','THREAD_START')},
  @{n='cobalt_strike_file_cleanup_or_timestomp_compensating_signal';sev='medium';p='CSB-026,CSB-034';desc="Correlates execution of a file with deletion of that same file path by an unsigned or rare process shortly afterward, covering self-deleting-artifact cleanup that the base rarity-only rule does not tie to prior execution.";lsp='Normalize PROCESS_LAUNCH and FILE_DELETE with matching full path, host, and process signer/prevalence on the deleting process, joined within 15 minutes.';fp='Installers, updaters, and self-extracting archives remain a false-positive source when they are unsigned or rare; the signer/prevalence gate narrows but does not eliminate this overlap.';evts=@('PROCESS_LAUNCH','FILE_DELETE')},
  @{n='cobalt_strike_powershell_or_clr_in_unusual_host_compensating_signal';sev='high';p='CSB-015,CSB-017';desc='Detects CLR/CoreCLR module load into an unsigned or rare process, providing an alternate detection path for in-memory .NET hosting when runtime-expected/CLR_RUNTIME_LOAD telemetry is unavailable.';lsp='Normalize MODULE_LOAD for clr.dll/coreclr.dll with process signer and prevalence.';fp='Custom .NET hosts, IDEs, installers, and management agents that legitimately embed the CLR in an uncommon or unsigned process.';evts=@('MODULE_LOAD')},
  @{n='cobalt_strike_process_network_context_compensating_signal';sev='high';p='CSB-001,CSB-002,CSB-005';desc='Detects low-variance periodic outbound connections from a rare-prevalence process to a rare destination, adding the classic beacon-interval and destination-novelty dimensions that the base rarity-only fan-in rule does not measure.';lsp='Normalize NETWORK_CONNECTION with process hash and prevalence, destination hostname and a destination-prevalence enrichment, and an interval-variance-bucket enrichment derived from inter-connection timing.';fp='Software updaters, telemetry/monitoring agents, and any low-jitter scheduled task that also happens to run from a rare process against a rare destination.';evts=@('NETWORK_CONNECTION')},
  @{n='cobalt_strike_sensitive_file_activity_compensating_signal';sev='high';p='CSB-024,CSB-025';desc='Aggregates sensitive-file reads by user and host across processes and correlates them with archive creation by the same user/host, covering multi-process collection where one process stages files and another compresses or transmits them.';lsp='Normalize FILE_READ with sensitivity classification, and FILE_WRITE for archive-extension targets, joined on host and user within 30 minutes.';fp='Backup, synchronization, DLP, indexing, and document-management tools that read multiple sensitive files and then write compressed archives.';evts=@('FILE_READ','FILE_WRITE')},
  @{n='cobalt_strike_sensitive_registry_read_compensating_signal';sev='medium';p='CSB-023';desc='Detects a single process reading several distinct sensitive-registry-family keys within a short window, surfacing multi-family enumeration bursts that the base single-event sensitivity check does not aggregate.';lsp='Normalize REGISTRY_READ with process hash, hostname, a registry-security-family classification field, and an approved-inventory-process enrichment, joined on host and process hash within 15 minutes.';fp='Inventory, compliance, EDR, backup, and forensics tooling that legitimately reads across many sensitive registry families; the approved-inventory-process enrichment is required to keep this usable.';evts=@('REGISTRY_READ')},
  @{n='cobalt_strike_service_or_integrity_transition_compensating_signal';sev='high';p='CSB-020';desc="Detects a process launch reaching SYSTEM integrity whose parent process is unsigned or rare and is not an approved elevation broker, providing the causal parent/child relationship that the base rule's standalone 4697/7045/integrity-transition signal does not require.";lsp='Normalize PROCESS_LAUNCH with target integrity level, parent process signer and prevalence, and an approved-elevation-broker enrichment.';fp='Installers, driver-installation flows, and approved elevation-broker components not reflected in the enrichment allowlist.';evts=@('PROCESS_LAUNCH')},
  @{n='cobalt_strike_socket_fanout_or_forwarding_compensating_signal';sev='high';p='CSB-009';desc='Correlates an inbound connection to a process with that same process subsequently creating multiple distinct outbound connections, detecting the relay/forwarding topology that the base outbound-only fan-out rule cannot express.';lsp='Normalize NETWORK_CONNECTION for both inbound and outbound direction with a stable process entity identifier, joined on host and process entity within 15 minutes.';fp='Browsers, approved proxies, EDR, backup, and orchestration agents that legitimately combine inbound acceptance with outbound fan-out.';evts=@('NETWORK_CONNECTION')},
  @{n='cobalt_strike_socket_listen_or_rare_egress_compensating_signal';sev='high';p='CSB-008';desc='Correlates a rare-process socket listen with an accepted inbound connection on the same port and process, closing the gap between merely listening and actually receiving a connection that the base standalone-listen rule leaves open.';lsp='Normalize SOCKET_LISTEN and inbound NETWORK_CONNECTION with a stable process entity identifier, process signer/prevalence, and port, joined on host, process entity and port within 30 minutes.';fp='Development tools and local services that legitimately listen from rare binaries and receive local or authorized connections.';evts=@('SOCKET_LISTEN','NETWORK_CONNECTION')},
  @{n='cobalt_strike_user_data_collection_compensating_signal';sev='high';p='CSB-027';desc='Correlates a user-data collection effect (screen, clipboard, input, or browser-secret) with an outbound network connection from the same process shortly afterward, distinguishing collection-then-egress from a single benign access that the base standalone-effect rule cannot separate.';lsp='Normalize vendor SCREEN_CAPTURE/CLIPBOARD_READ/INPUT_CAPTURE/BROWSER_SECRET_READ and outbound NETWORK_CONNECTION with a stable process entity identifier, joined on host and process entity within 15 minutes.';fp='Assistive technology, conferencing, remote support, password managers, browsers, and approved monitoring software that both collect and transmit data as part of normal operation.';evts=@('SCREEN_CAPTURE','CLIPBOARD_READ','INPUT_CAPTURE','BROWSER_SECRET_READ','NETWORK_CONNECTION')}
)

foreach ($i in $items) {
  $rulePath = Join-Path $det ('yaral\' + $i.n + '.yaral')
  $hash = (Get-FileHash $rulePath -Algorithm SHA256).Hash.ToLower()
  $evtList = ($i.evts | ForEach-Object { '"' + $_ + '"' }) -join ', '
  $evtListSq = ($i.evts | ForEach-Object { "'" + $_ + "'" }) -join ', '
  $assumptions = "Candidate retrieval is translated; canonical entity joins, ordering, windows, cardinality, and enrichment-field mappings must be implemented and tested in the target backend before use."
  $refs = "reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/$($i.n -replace '_compensating_signal$','').md"

  # SPL
  $spl = @"
# source_yaral: detections/cobalt-strike-beacon/yaral/$($i.n).yaral
# source_sha256: $hash
# translation_status: experimental_needs_backend_mapping_and_validation
# fidelity: partial
# rule_name: $($i.n)
# severity: $($i.sev)
# procedure_ids: $($i.p)
# description: $($i.desc)
# log_source_prerequisites: $($i.lsp)
# false_positives: $($i.fp)
# references: $refs
# assumptions_and_gaps: $assumptions
# schema_profile: schemas/splunk-cim.yml
index=<configured_index>
| where in(coalesce('metadata.product_event_type','metadata.event_type'), $evtList)
| eval canonical_rule="$($i.n)"
| stats count values('metadata.product_event_type') as observed_event_types by 'principal.hostname', 'principal.user.userid'
| where count > 0
"@
  Set-Content -LiteralPath (Join-Path $det ('spl\' + $i.n + '.spl')) -Value $spl -Encoding utf8

  # KQL
  $kql = @"
// source_yaral: detections/cobalt-strike-beacon/yaral/$($i.n).yaral
// source_sha256: $hash
// translation_status: experimental_needs_backend_mapping_and_validation
// fidelity: partial
// rule_name: $($i.n)
// severity: $($i.sev)
// procedure_ids: $($i.p)
// description: $($i.desc)
// log_source_prerequisites: $($i.lsp)
// false_positives: $($i.fp)
// references: $refs
// assumptions_and_gaps: $assumptions
// schema_profile: schemas/sentinel-asim.yml
NormalizedEvents
| where ProductEventType in ($evtList) or EventType in ($evtList)
| summarize EventCount=count(), ObservedEventTypes=make_set(ProductEventType) by Hostname, UserId
| where EventCount > 0
| extend CanonicalRule="$($i.n)"
"@
  Set-Content -LiteralPath (Join-Path $det ('kql\' + $i.n + '.kql')) -Value $kql -Encoding utf8

  # SQL
  $sql = @"
-- source_yaral: detections/cobalt-strike-beacon/yaral/$($i.n).yaral
-- source_sha256: $hash
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: $($i.n)
-- severity: $($i.sev)
-- procedure_ids: $($i.p)
-- description: $($i.desc)
-- log_source_prerequisites: $($i.lsp)
-- false_positives: $($i.fp)
-- references: $refs
-- assumptions_and_gaps: $assumptions
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       '$($i.n)' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ($evtListSq) OR event_type IN ($evtListSq)
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
"@
  Set-Content -LiteralPath (Join-Path $det ('sql\' + $i.n + '.sql')) -Value $sql -Encoding utf8

  # EQL
  $eql = @"
// source_yaral: detections/cobalt-strike-beacon/yaral/$($i.n).yaral
// source_sha256: $hash
// translation_status: experimental_needs_backend_mapping_and_validation
// fidelity: partial
// rule_name: $($i.n)
// severity: $($i.sev)
// procedure_ids: $($i.p)
// description: $($i.desc)
// log_source_prerequisites: $($i.lsp)
// false_positives: $($i.fp)
// references: $refs
// assumptions_and_gaps: $assumptions
// schema_profile: schemas/elastic-ecs.yml
// ECS assumption: event.code carries product IDs and event.action carries normalized event types.
any where event.code in ($evtList) or event.action in ($evtList)
"@
  Set-Content -LiteralPath (Join-Path $det ('eql\' + $i.n + '.eql')) -Value $eql -Encoding utf8

  # Sigma
  $fpYaml = $i.fp -replace '"','\"'
  $descYaml = $i.desc -replace '"','\"'
  $lspYaml = $i.lsp -replace '"','\"'
  $sigma = @"
title: "$descYaml"
name: $($i.n)
status: experimental
description: "$descYaml"
source_yaral: "detections/cobalt-strike-beacon/yaral/$($i.n).yaral"
source_sha256: "$hash"
translation_status: experimental_needs_backend_mapping_and_validation
fidelity: partial
schema_profile: schemas/sigma.yml
assumptions_and_gaps: "$assumptions"
references:
  - "reports/cobalt-strike-beacon/source-analysis.md"
  - "public-rules/comparisons/cobalt-strike-beacon/$($i.n -replace '_compensating_signal$','').md"
procedure_ids: "$($i.p)"
log_source_prerequisites: "$lspYaml"
logsource:
  category: generic
detection:
  selection_event_type:
    event.code: [$evtList]
  condition: selection_event_type
falsepositives:
  - "$fpYaml"
level: $($i.sev)
"@
  Set-Content -LiteralPath (Join-Path $det ('sigma\' + $i.n + '.yml')) -Value $sigma -Encoding utf8
}

Write-Host "Generated translations for $($items.Count) compensating-signal rules."
