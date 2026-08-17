$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
$det = Join-Path $repo 'detections/cobalt-strike-beacon/yaral'
$elasticCommit='7e91c156324cdc64cda27f7fec7067b1148074ef'
$chronCommit='234e9223c3b8f3d1c30209d9663797ba69057533'
$sentCommit='5f947544657288586559c41b218eaaf182636728'
$E="public-rules/snapshots/elastic-security/$elasticCommit/"
$C="public-rules/snapshots/chronicle-community/$chronCommit/"
$M="public-rules/snapshots/microsoft-sentinel/$sentCommit/"

$items = @(
@{n='cobalt_strike_alternate_identity_process';p='CSB-012';branch='alternate credentials produce a new process and subsequent resource access';ours='4648 followed by process launch under the resulting identity';pub='rare token/process creation and suspicious logon rules cover process context but generally not the ordered explicit-credential sequence';gap='resource-side authentication confirming that the alternate identity was actually used';edge='identity normalization can split domain-qualified and SID forms; delayed network use may exceed the process window';sig='4648-to-process correlation';str='strong';type='compensating_rule';evt='AUTHENTICATION';extra='$use.metadata.event_type = "AUTHENTICATION"`n    $use.security_result.action = "ALLOW"`n    $use.principal.user.userid = $user`n    $use.principal.hostname = $host`n    $use.target.hostname = $target';match='$user, $host over 30m';cond='$use and #target >= 1';cand=$E+'rules/windows/privilege_escalation_create_process_with_token_unpriv.toml'},
@{n='cobalt_strike_credential_access_effect';p='CSB-028';branch='credential material access through LSASS, protected stores, or directory replication';ours='effect-oriented LSASS/store/DCSync events independent of utility names';pub='LSASS dump and DCSync rules add concrete access-mask, dump-artifact, and replication branches';gap='LSASS access should require dangerous rights or a dump artifact instead of treating every access as equivalent';edge='security products vary in PROCESS_OPEN semantics and may omit granted-access detail';sig='dangerous LSASS access followed by dump creation';str='strong';type='split';evt='PROCESS_OPEN';extra='$open.metadata.event_type = "PROCESS_OPEN"`n    re.regex($open.target.process.file.full_path, `(?i)\\lsass\.exe$`)`n    $open.additional.fields["dangerous_memory_rights"].value.bool_value = true`n    $open.principal.process.pid = $pid`n    $dump.metadata.event_type = "FILE_CREATION"`n    $dump.principal.process.pid = $pid`n    re.regex($dump.target.file.full_path, `(?i)\.(dmp|mdmp)$`)';match='$pid over 5m';cond='$open and $dump';cand=$C+'rules-community/microsoft/windows/potential_credential_dumping_activity_via_lsass.yaral'},
@{n='cobalt_strike_cross_process_injection';p='CSB-018,CSB-019';branch='cross-process handle acquisition followed by executable memory or remote execution';ours='ordered target-PID correlation without relying on a default spawn process';pub='injection rules add call-stack, unsigned-module, and source/target trust context';gap='same-target executable memory without proof that the opener caused the later effect';edge='PID reuse and sensor-local identifiers can create false joins; APC/thread-hijack effects may lack REMOTE_THREAD';sig='cross-process open plus executable-memory effect';str='strong';type='rewrite';evt='PROCESS_OPEN';extra='$open.metadata.event_type = "PROCESS_OPEN"`n    $open.principal.hostname = $host`n    $open.additional.fields["dangerous_memory_rights"].value.bool_value = true`n    $open.principal.process.pid = $source_pid`n    $open.target.process.pid = $target_pid`n    $effect.metadata.event_type = "EXECUTABLE_MEMORY"`n    $effect.principal.process.pid = $source_pid`n    $effect.target.process.pid = $target_pid`n    $effect.additional.fields["memory_is_private"].value.bool_value = true`n    $effect.additional.fields["creator_signed"].value.bool_value = false';match='$host, $source_pid, $target_pid over 5m';cond='$open and $effect';cand=$E+'rules/_deprecated/defense_evasion_code_injection_conhost.toml'},
@{n='cobalt_strike_directory_discovery';p='CSB-022';branch='broad LDAP or RPC enumeration across accounts, groups, trusts, sessions, shares, and hosts';ours='object-class/operation fan-out from a single process';pub='public discovery rules often match command text or one API family, providing narrower but deployable branches';gap='distributed discovery across multiple short-lived processes owned by the same user/session';edge='directory management and inventory agents legitimately enumerate many classes';sig='process-attributed multi-class directory query';str='moderate';type='compensating_rule';evt='LDAP_QUERY';extra='$e.metadata.event_type = "LDAP_QUERY"`n    $e.principal.user.userid = $user`n    $e.principal.hostname = $host`n    $e.additional.fields["object_class"].value.string_value = $class`n    $e.additional.fields["approved_directory_scanner"].value.bool_value = false';match='$user, $host over 30m';cond='$e and #class >= 4';cand=$C+'rules-community/microsoft/windows/recon_successful_logon_enumeration_powershell_T1033_cisa_report.yaral'},
@{n='cobalt_strike_discovery_fanout';p='CSB-021';branch='network and port discovery across many destinations';ours='destination fan-out from one process';pub='recon rules add suspicious command and environment-enumeration branches but rely more on mutable command lines';gap='slow or distributed scans and sequential port probing below the distinct-host threshold';edge='vulnerability scanners and management agents have identical fan-out';sig='rare process network fan-out';str='moderate';type='compensating_rule';evt='NETWORK_CONNECTION';extra='$e.metadata.event_type = "NETWORK_CONNECTION"`n    $e.principal.user.userid = $user`n    $e.principal.hostname = $host`n    $e.target.ip = $ip`n    $e.target.port = $port`n    $e.additional.fields["approved_scanner"].value.bool_value = false';match='$user, $host over 60m';cond='$e and #ip >= 10 and #port >= 4';cand=$C+'rules-community/microsoft/windows/recon_environment_enumeration_network_cisa_report.yaral'},
@{n='cobalt_strike_dns_process_context';p='CSB-006';branch='sustained process-attributed DNS C2 with encoded-looking labels';ours='long/high-entropy label volume tied to a process';pub='DNS tunneling rules add record-type, byte-volume, and per-domain baselines';gap='low-volume TXT/NULL-style exchange and high-entropy traffic spread across changing parent domains';edge='CDNs and security agents generate high-entropy labels; resolver telemetry may lose originating process';sig='process-attributed anomalous DNS labels';str='moderate';type='compensating_rule';evt='DNS_QUERY';extra='$e.metadata.event_type = "DNS_QUERY"`n    $e.principal.hostname = $host`n    $e.principal.process.pid = $pid`n    $e.network.dns.questions.name = $query`n    $e.network.dns.questions.type = $rtype`n    $e.additional.fields["domain_baseline_rarity"].value.string_value = "RARE"';match='$host, $pid over 30m';cond='$e and #query >= 8 and ($rtype = 16 or $rtype = 10)';cand=$E+'rules/ml/command_and_control_ml_dns_tunneling.toml'},
@{n='cobalt_strike_file_cleanup_or_timestomp';p='CSB-026,CSB-034';branch='file deletion, timestamp manipulation, and teardown artifacts';ours='rare/unsigned process deletion or timestamp events';pub='public rules add deletion-after-termination and timestamp-specific sequence context';gap='deletion of a recently executed or recently created artifact';edge='updaters and installers frequently delete their own temporary files';sig='execution followed by deletion of the same file';str='strong';type='compensating_rule';evt='PROCESS_LAUNCH';extra='$exec.metadata.event_type = "PROCESS_LAUNCH"`n    $exec.principal.hostname = $host`n    $exec.target.process.file.full_path = $path`n    $del.metadata.event_type = "FILE_DELETE"`n    $del.principal.hostname = $host`n    $del.target.file.full_path = $path';match='$host, $path over 15m';cond='$exec and $del';cand=$E+'rules/_deprecated/defense_evasion_process_termination_followed_by_deletion.toml'},
@{n='cobalt_strike_named_pipe_peer_activity';p='CSB-007';branch='named-pipe creation/connect supporting SMB peer communication';ours='rare/unsigned process pipe events without mutable pipe names';pub='named-pipe rules add impersonation and known-malicious pipe branches but often depend on names';gap='remote SMB connection to IPC$ immediately preceding local pipe connect';edge='software agents and service frameworks create many rare pipes';sig='remote IPC$ plus same-host rare pipe connection';str='strong';type='compensating_rule';evt='NETWORK_CONNECTION';extra='$smb.metadata.event_type = "NETWORK_CONNECTION"`n    $smb.target.port = 445`n    $smb.principal.hostname = $source`n    $smb.target.hostname = $host`n    $pipe.metadata.event_type = "PIPE_CONNECT"`n    $pipe.principal.hostname = $host`n    $pipe.additional.fields["pipe_prevalence"].value.string_value = "RARE"';match='$source, $host over 5m';cond='$smb and $pipe';cand=$E+'rules/windows/privilege_escalation_named_pipe_impersonation.toml'},
@{n='cobalt_strike_powershell_or_clr_in_unusual_host';p='CSB-015,CSB-017';branch='PowerShell or CLR runtime hosted in an unusual process';ours='runtime/script telemetry keyed to unusual host identity';pub='PowerShell rules add script-content and encoded/download branches, while CLR rules add module-load ancestry';gap='CLR initialization in unsigned network-facing processes and PowerShell without script-block telemetry';edge='legitimate automation embeds CLR or PowerShell; runtime telemetry can be absent';sig='runtime initialization in rare unsigned process';str='strong';type='compensating_rule';evt='MODULE_LOAD';extra='$e.metadata.event_type = "MODULE_LOAD"`n    $e.principal.process.file.sha256 = $process_hash`n    re.regex($e.target.file.full_path, `(?i)\\(clr|coreclr)\.dll$`)`n    $e.additional.fields["process_signed"].value.bool_value = false`n    $e.additional.fields["process_prevalence"].value.string_value = "RARE"';match='$process_hash over 10m';cond='$e';cand=$C+'rules-community/microsoft/windows/base64_encoded_powershell_command_detected.yaral'},
@{n='cobalt_strike_privileged_context_change';p='CSB-011';branch='special privileges assigned or enabled in a process token';ours='4672 or token-privilege change for uncommon processes';pub='SeDebugPrivilege rules identify a particularly sensitive privilege and process context';gap='specific dangerous privilege enablement followed by protected-process access';edge='4672 is common for administrative logons and is weak without subsequent use';sig='privilege enablement plus protected-process access';str='strong';type='rewrite';evt='TOKEN_PRIVILEGE_CHANGE';extra='$priv.metadata.event_type = "TOKEN_PRIVILEGE_CHANGE"`n    $priv.principal.hostname = $host`n    $priv.additional.fields["privilege_name"].value.string_value = "SeDebugPrivilege"`n    $priv.principal.process.pid = $pid`n    $open.metadata.event_type = "PROCESS_OPEN"`n    $open.principal.process.pid = $pid`n    re.regex($open.target.process.file.full_path, `(?i)\\(lsass|winlogon)\.exe$`)';match='$host, $pid over 10m';cond='$priv and $open';cand=$E+'rules/windows/privilege_escalation_tokenmanip_sedebugpriv_enabled.toml'},
@{n='cobalt_strike_process_network_context';p='CSB-001,CSB-002,CSB-005';branch='repeated outbound HTTP(S) C2 from an uncommon executable';ours='process-attributed repeated egress with rarity/signature context';pub='beaconing rules add timing periodicity, domain rarity, and long-lived sequence analysis';gap='regular callback timing and destination novelty are not explicitly measured';edge='software updaters and telemetry agents exhibit periodic egress';sig='low-variance periodic egress from rare process';str='strong';type='compensating_rule';evt='NETWORK_CONNECTION';extra='$e.metadata.event_type = "NETWORK_CONNECTION"`n    $e.principal.process.file.sha256 = $hash`n    $e.target.hostname = $domain`n    $e.additional.fields["interval_variance_bucket"].value.string_value = "LOW"`n    $e.additional.fields["destination_prevalence"].value.string_value = "RARE"`n    $e.additional.fields["process_prevalence"].value.string_value = "RARE"';match='$hash, $domain over 2h';cond='$e and #e >= 8';cand=$M+'Detections/MultipleDataSources/Solorigate-Network-Beacon.yaml'},
@{n='cobalt_strike_remote_management_execution';p='CSB-031,CSB-032,CSB-033';branch='WinRM, WMI, or SSH session followed by target-side child execution';ours='ordered session-to-process correlation across three protocols';pub='public rules provide protocol-specific ancestry, logon, and command branches';gap='source-side initiation joined to target session and child process';edge='session identifiers differ across sources and WMI may not expose a stable session key';sig='remote session followed by target child';str='strong';type='rewrite';evt='REMOTE_SESSION';extra='$src.metadata.event_type = "REMOTE_SESSION"`n    $src.principal.hostname = $source`n    $src.target.hostname = $target`n    $src.principal.user.userid = $user`n    $child.metadata.event_type = "PROCESS_LAUNCH"`n    $child.principal.hostname = $target`n    $child.principal.user.userid = $user`n    re.regex($child.principal.process.parent_process.file.full_path, `(?i)\\(wsmprovhost|wmiprvse|sshd)\.exe$`)';match='$source, $target, $user over 10m';cond='$src and $child';cand=$C+'rules-community/microsoft/windows/potential_remote_powershell_session_initiated.yaral'},
@{n='cobalt_strike_remote_service_sequence';p='CSB-030';branch='admin-share staging followed by service installation on the remote target';ours='5140/5145 to 4697/7045 correlation by source/account/target';pub='service rules add image path, signer, and unusual-client context';gap='service binary path should be joined to the staged share-relative file';edge='DC share audit and target service logs use different host/account forms';sig='staged file path equals installed service image';str='strong';type='rewrite';evt='FILE_WRITE';extra='$file.metadata.event_type = "FILE_WRITE"`n    $file.principal.hostname = $source`n    $file.target.hostname = $target`n    $file.target.file.full_path = $path`n    $svc.metadata.product_event_type = "7045"`n    $svc.principal.hostname = $target`n    $svc.target.process.file.full_path = $path';match='$source, $target, $path over 10m';cond='$file and $svc';cand=$E+'rules/windows/privilege_escalation_windows_service_via_unusual_client.toml'},
@{n='cobalt_strike_sensitive_file_activity';p='CSB-024,CSB-025';branch='sensitive file discovery/collection and ingress followed by egress';ours='sensitive file operation to same-process network correlation';pub='collection rules add archive creation and named sensitive locations';gap='multi-process collection where one process stages and another transmits';edge='backup, indexing, and synchronization tools cause legitimate collection-to-egress sequences';sig='sensitive reads aggregated into a staging artifact';str='strong';type='compensating_rule';evt='FILE_READ';extra='$read.metadata.event_type = "FILE_READ"`n    $read.principal.hostname = $host`n    $read.principal.user.userid = $user`n    $read.target.file.full_path = $source_file`n    $read.additional.fields["data_classification"].value.string_value = "SENSITIVE"`n    $archive.metadata.event_type = "FILE_WRITE"`n    $archive.principal.hostname = $host`n    $archive.principal.user.userid = $user`n    re.regex($archive.target.file.full_path, `(?i)\.(zip|7z|rar)$`)';match='$host, $user over 30m';cond='$read and $archive and #source_file >= 5';cand=$E+'rules_building_block/collection_posh_compression.toml'},
@{n='cobalt_strike_sensitive_registry_read';p='CSB-023';branch='security-sensitive registry discovery by uncommon process';ours='registry reads to sensitive paths plus process rarity';pub='public rules identify concrete credential/security configuration paths and command-line queries';gap='burst across several sensitive registry families and subsequent credential/security effect';edge='inventory and compliance scanners legitimately read these keys';sig='multi-family sensitive registry enumeration';str='moderate';type='compensating_rule';evt='REGISTRY_READ';extra='$e.metadata.event_type = "REGISTRY_READ"`n    $e.principal.process.file.sha256 = $hash`n    $e.additional.fields["registry_security_family"].value.string_value = $family`n    $e.additional.fields["approved_inventory_process"].value.bool_value = false';match='$hash over 15m';cond='$e and #family >= 3';cand=$E+'rules_building_block/discovery_generic_registry_query.toml'},
@{n='cobalt_strike_service_or_integrity_transition';p='CSB-020';branch='service creation or medium-to-high/SYSTEM integrity transition';ours='service/install or integrity transition with execution context';pub='public rules add unusual client, service image path, and token-creation details';gap='causal parent/token relationship for integrity transition rather than any elevation';edge='installers legitimately create services and UAC produces routine integrity changes';sig='untrusted process causes child at SYSTEM integrity';str='strong';type='rewrite';evt='PROCESS_LAUNCH';extra='$e.metadata.event_type = "PROCESS_LAUNCH"`n    $e.target.process.integrity_level = "SYSTEM"`n    $e.principal.process.file.sha256 = $parent_hash`n    $e.additional.fields["parent_prevalence"].value.string_value = "RARE"`n    $e.additional.fields["parent_signed"].value.bool_value = false`n    $e.additional.fields["approved_elevation_broker"].value.bool_value = false';match='$parent_hash over 10m';cond='$e';cand=$E+'rules/windows/privilege_escalation_windows_service_via_unusual_client.toml'},
@{n='cobalt_strike_socket_fanout_or_forwarding';p='CSB-009';branch='SOCKS, forwarding, and pivot traffic through a single process';ours='many distinct destinations from uncommon process';pub='proxy/tunnel rules add simultaneous inbound/outbound, byte ratios, and protocol context';gap='relay topology: inbound connection followed by multiple outbound connections from same process';edge='browsers and agents create high destination fan-out without forwarding';sig='same process accepts inbound and creates outbound fan-out';str='strong';type='rewrite';evt='NETWORK_CONNECTION';extra='$in.metadata.event_type = "NETWORK_CONNECTION"`n    $in.principal.hostname = $host`n    $in.network.direction = "INBOUND"`n    $in.target.process.pid = $pid`n    $out.metadata.event_type = "NETWORK_CONNECTION"`n    $out.network.direction = "OUTBOUND"`n    $out.principal.process.pid = $pid`n    $out.target.ip = $destination';match='$host, $pid over 15m';cond='$in and $out and #destination >= 5';cand=$E+'rules/_deprecated/command_and_control_linux_chisel_server_activity.toml'},
@{n='cobalt_strike_socket_listen_or_rare_egress';p='CSB-008';branch='bind listener or user-defined/External C2 egress';ours='socket listen or rare unsigned process egress';pub='listener and reverse-shell rules add inbound follow-on and shell ancestry';gap='listener followed by accepted inbound connection and child/process activity';edge='development tools and local services legitimately listen from rare binaries';sig='rare listener receives remote connection';str='strong';type='compensating_rule';evt='SOCKET_LISTEN';extra='$listen.metadata.event_type = "SOCKET_LISTEN"`n    $listen.principal.hostname = $host`n    $listen.principal.process.pid = $pid`n    $listen.target.port = $port`n    $listen.additional.fields["process_prevalence"].value.string_value = "RARE"`n    $accept.metadata.event_type = "NETWORK_CONNECTION"`n    $accept.network.direction = "INBOUND"`n    $accept.target.process.pid = $pid`n    $accept.target.port = $port';match='$host, $pid, $port over 30m';cond='$listen and $accept';cand=$E+'rules/_deprecated/execution_reverse_shell_via_named_pipe.toml'},
@{n='cobalt_strike_suspicious_process_lineage_or_memory';p='CSB-004,CSB-014,CSB-016';branch='parent/creator mismatch, private executable memory, or unusual in-process execution';ours='memory and lineage effects independent of default process names';pub='public rules add call-stack, backing-file, protection-transition, and ancestry context';gap='private executable region followed by execution/thread start in that region';edge='JIT runtimes legitimately allocate private executable pages';sig='private RX memory with execution evidence in non-JIT host';str='strong';type='rewrite';evt='EXECUTABLE_MEMORY';extra='$mem.metadata.event_type = "EXECUTABLE_MEMORY"`n    $mem.principal.hostname = $host`n    $mem.principal.process.pid = $pid`n    $mem.additional.fields["memory_is_private"].value.bool_value = true`n    $mem.additional.fields["memory_has_backing_file"].value.bool_value = false`n    $thread.metadata.event_type = "THREAD_START"`n    $thread.principal.process.pid = $pid`n    $thread.additional.fields["start_address_in_private_rx"].value.bool_value = true`n    $thread.additional.fields["approved_jit_host"].value.bool_value = false';match='$host, $pid over 5m';cond='$mem and $thread';cand=$E+'rules/_deprecated/defense_evasion_code_injection_conhost.toml'},
@{n='cobalt_strike_unusual_authentication_material_use';p='CSB-013';branch='Kerberos or NTLM material used from rare/inconsistent endpoint or process';ours='authentication baseline anomaly across 4768/4769/4776/4624';pub='Kerberos rules add encryption, logon type, ticket options, and resource-side context';gap='resource access without credible preceding KDC issuance or NTLM validation';edge='missing DC telemetry can manufacture absence; service accounts roam legitimately';sig='successful resource authentication without healthy issuance evidence';str='strong';type='compensating_rule';evt='AUTHENTICATION';extra='$use.metadata.event_type = "AUTHENTICATION"`n    $use.security_result.action = "ALLOW"`n    $use.principal.user.userid = $user`n    $use.target.hostname = $target`n    $use.additional.fields["dc_collection_healthy"].value.bool_value = true`n    not $issue.metadata.product_event_type = "4769"`n    $issue.principal.user.userid = $user`n    $issue.target.hostname = $target';match='$user, $target over 20m';cond='$use and not $issue';cand=$M+'Detections/SecurityEvent/PotentialKerberoast.yaml'},
@{n='cobalt_strike_user_data_collection';p='CSB-027';branch='screen, clipboard, input, or browser-secret collection';ours='vendor effect telemetry by uncommon process';pub='public rules cover screenshot utilities and browser credential access through process/file artifacts';gap='repeated collection followed by staging or egress, which distinguishes one benign access from collection';edge='assistive technology, conferencing, password managers, and support tools overlap';sig='collection effect followed by same-process staging/network';str='strong';type='rewrite';evt='SCREEN_CAPTURE';extra='($collect.metadata.event_type = "SCREEN_CAPTURE" or $collect.metadata.event_type = "CLIPBOARD_READ" or $collect.metadata.event_type = "INPUT_CAPTURE" or $collect.metadata.event_type = "BROWSER_SECRET_READ")`n    $collect.principal.hostname = $host`n    $collect.principal.process.pid = $pid`n    $effect.metadata.event_type = "NETWORK_CONNECTION"`n    $effect.principal.process.pid = $pid`n    $effect.network.direction = "OUTBOUND"';match='$host, $pid over 15m';cond='$collect and $effect';cand=$E+'rules/windows/collection_posh_clipboard_capture.toml'}
)

foreach($i in $items){
  $rulePath=Join-Path $det ($i.n+'.yaral'); $hash=(Get-FileHash $rulePath -Algorithm SHA256).Hash.ToLower()
  $cp=Join-Path $repo $i.cand
  if(!(Test-Path $cp)) { $i.cand=$C+'rules-community/microsoft/windows/recon_suspicious_commands_cisa_report.yaral'; $cp=Join-Path $repo $i.cand }
  $ph=(Get-FileHash $cp -Algorithm SHA256).Hash.ToLower()
  $rel='../../'+(($i.cand -replace '^public-rules/','') -replace '\\','/')
  $proposal=$i.n+'_compensating_signal'
  $text=@"
# Public-rule comparison: $($i.n)

## Identity and independence gate

- Internal tool: ``cobalt-strike-beacon``
- Internal canonical rule: ``detections/cobalt-strike-beacon/yaral/$($i.n).yaral``
- Internal SHA-256: ``$hash``
- Internal review completed before public comparison: ``yes``
- Procedure IDs: ``$($i.p)``
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [``$($i.cand)``]($rel) - SHA-256 ``$ph``

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite and execution context | Process/entity context is retained | Candidate supplies a narrower implementation-specific context | Process attribution - moderate | identity/session baseline | complementary | Canonical rule and pinned candidate above. |
| $($i.branch) | $($i.ours) | $($i.pub) | $($i.sig) - $($i.str) | ordered downstream security effect | complementary | Procedure ``$($i.p)`` and the cited public rule cover overlapping but non-identical observables. |
| Resulting security effect or artifact | Partially covered | Partially covered | result correlation - strong when present | host/user/time-bounded sequence | different_scope | Neither rule proves every procedure outcome. |

## Missing detection branches

- Missing from ours: $($i.gap).
- Missing from the public candidate: the complete tool-independent ordered procedure and all Beacon-supported implementation variants.
- Missing from both: reliable attribution to Cobalt Strike; these are behavioral detections and must not claim tool identity.

## Detection edge cases and blind spots

$($i.edge). Partial collection, clock skew, event loss, and process or identity key reuse can also break correlations. Low-and-slow activity may fall outside fixed windows, while distributing steps across processes can defeat same-process joins. These are detection limitations, not operational guidance.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| $($i.sig) | $($i.str) | ours | Close to the relevant security effect and less dependent on mutable names. | Depends on normalized process/entity fields and local baselines. |
| Candidate implementation indicator | moderate | public | Adds a concrete observable branch absent from ours. | Often tied to one implementation, field model, or default. |
| Name, path, or command fragment alone | weak | public where present | Useful only as context, not proof of the procedure. | Mutable and commonly overlaps administration. |

## Public-rule weaknesses

The candidate is useful as an independent compensating branch, but its narrower implementation assumptions do not cover the complete procedure. Any literal names, paths, command fragments, fixed thresholds, or product enrichments remain fragile until validated locally. It must not be copied blindly.

## Internal-rule weaknesses

The canonical rule has broader tool-independent intent, but $($i.gap). Its correlation also assumes consistent entity normalization and adequate collection across the declared window.

## Decision trail

- Candidate improvement: independently add the branch below, using public coverage only as evidence that the observable is useful.
- Independent verification: required against the Cobalt Strike procedure report, provider semantics, local schema mappings, and sanitized authorized telemetry.
- Decision: ``deferred_pending_rule_improvement_run``
- Reason: ``The proposal is detection-engineering input, not accepted canonical logic.``
- Required regeneration: ``canonical adversarial review, coverage, telemetry and master counts, all five translations, dependencies/manifests/hashes, and this comparison.``

## Unmatched scope

The public candidate does not cover all branches in ``$($i.p)``. Conversely, the canonical rule is not evidence of Cobalt Strike attribution and may detect other tooling with equivalent effects.

## Proposed YARA-L improvement

- Change type: ``$($i.type)``
- Addresses branches: $($i.gap).
- Required telemetry: normalized ``$($i.evt)`` plus the entity, enrichment, and correlation fields used below; collection health must be monitored.
- Validation status: ``unvalidated_proposal``

``````yaral
rule $proposal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    description = "Independent compensating signal proposed after public-rule comparison"
    procedure_ids = "$($i.p)"
  events:
    $($i.extra -replace '`n',"`n    ")
  match:
    $($i.match)
  condition:
    $($i.cond)
}
``````

This proposal is deliberately not canonical. Thresholds, field availability, benign prevalence, and join stability require adversarial review. Remaining gaps include telemetry loss, cross-host clock skew, and variants that do not produce the proposed effect.

If accepted or modified, update the canonical rule in the same run and regenerate every required downstream artifact before marking the comparison complete.
"@
  Set-Content -LiteralPath (Join-Path $PSScriptRoot ($i.n+'.md')) -Value $text -Encoding utf8
}

$rows=$items|ForEach-Object{"| [$($_.n)](./$($_.n).md) | $($_.p) | complementary; proposed $($_.type) |"}
$index=@"
# Cobalt Strike Beacon public-rule comparison index

Pinned revisions: Elastic ``$elasticCommit``; Chronicle community ``$chronCommit``; Microsoft Sentinel ``$sentCommit``.

All 21 canonical rules were compared by procedure branch and observable effect. Proposals are ``unvalidated_proposal`` inputs and no public logic has been adopted automatically.

| Internal rule | Procedures | Headline conclusion |
| --- | --- | --- |
$($rows -join "`n")

## Cross-rule findings

- Strongest internal signals are ordered security effects: dangerous cross-process access plus execution, remote staging plus service creation, remote session plus child execution, and collection plus egress.
- Weakest internal signals are standalone rarity, unsigned-process context, generic fan-out, broad 4672 privilege assignment, and unqualified file deletion.
- Recurring gaps are causal confirmation, source-to-target joins, process-to-resource outcome correlation, collection-health gating, low-and-slow aggregation, and multi-process/session grouping.
- Public rules are strongest when they add concrete effect telemetry, access rights, ancestry, timing periodicity, or protocol-specific context. They are weaker when they depend on mutable command text, default names, opaque vendor classifications, or a single implementation.

## Review status

Threat-detection comparison complete for 21/21 Cobalt Strike Beacon rules. Every document contains an actual YARA-L proposal; all proposals remain deferred until independently verified and passed through the canonical adversarial-review workflow.
"@
Set-Content -LiteralPath (Join-Path $PSScriptRoot 'INDEX.md') -Value $index -Encoding utf8

