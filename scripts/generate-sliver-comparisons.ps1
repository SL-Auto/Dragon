$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$chron = 'public-rules/snapshots/chronicle-community/234e9223c3b8f3d1c30209d9663797ba69057533'
$elastic = 'public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef'
$pub = @{
 service="$chron/rules-community/microsoft/windows/win_susp_or_malicious_service_created.yaral"
 registry="$elastic/rules/windows/persistence_registry_uncommon.toml"
 cleanup="$elastic/rules/linux/defense_evasion_log_files_deleted.toml"
 dns="$elastic/rules/ml/command_and_control_ml_dns_tunneling.toml"
 proxy="$chron/rules-community/microsoft/windows/port_proxy_forwarding_T1090_cisa_report.yaral"
 shell="$elastic/rules/windows/execution_command_shell_started_by_unusual_process.toml"
 access="$chron/rules-community/microsoft/windows/hacktool_generic_process_access.yaral"
 beacon="$elastic/rules/integrations/beaconing/command_and_control_beaconing.toml"
 remote="$elastic/rules/windows/lateral_movement_remote_services.toml"
 screen="$elastic/rules/linux/collection_potential_video_recording_or_screenshot_activity.toml"
}
# Each entry states the security branch, the gap being closed, and a pinned adjacent public rule.
$d = @(
 @{n='sliver_browser_debugging_from_network_process';p='PROC-022';c='none';b='network-active process starts a browser debugging endpoint';g='The join does not require a debugging switch, bind address, listener, or browser child identity';s='browser process with debugging option plus local listener and parent egress';t='rewrite'},
 @{n='sliver_cleanup_after_egress';p='PROC-002,PROC-026';c='cleanup';b='egressing process removes its image or operational artifacts';g='Deletion and network events can be unrelated on a busy host because stable process and file identity are not proven';s='same process entity deletes its executable after egress';t='rewrite'},
 @{n='sliver_dns_or_udp_process_egress';p='PROC-004';c='dns';b='DNS or UDP transport with repeated process-attributed egress';g='A volume threshold misses low-rate sessions and does not distinguish resolver DNS, direct DNS, WireGuard-like UDP, or destination novelty';s='first-seen process-to-UDP destination with periodic recurrence';t='compensating_rule'},
 @{n='sliver_file_activity_from_network_process';p='PROC-007,PROC-008,PROC-009';c='none';b='network-active process reads, mutates, stages, or deletes files';g='Generic file activity is common and the rule conflates credential access, collection, transfer staging, and cleanup';s='sensitive-file access or archive/staging burst by the same process entity';t='split'},
 @{n='sliver_identity_or_service_from_network_process';p='PROC-016,PROC-017,PROC-019';c='service';b='network-active identity performs explicit-credential, privilege, or service operations';g='Four event families with different meanings are conflated and account-based correlation can join unrelated processes';s='stable process/logon session joined to explicit credentials and resulting privileged action';t='split'},
 @{n='sliver_listener_with_egress';p='PROC-005,PROC-021';c='proxy';b='one process accepts inbound traffic and establishes outbound transport';g='Legitimate proxies share this shape; listener role, destination novelty, connection acceptance and byte direction are absent';s='unapproved process accepts inbound and forwards to a first-seen destination';t='rewrite'},
 @{n='sliver_parent_egress_with_spawned_interpreter';p='PROC-010';c='shell';b='egressing parent creates a command interpreter';g='Interpreter naming is mutable and the rule lacks parent process identity, command provenance, token, and child network/result context';s='same process entity with egress creates a child carrying inherited anomalous network or token context';t='rewrite'},
 @{n='sliver_process_access_from_network_process';p='PROC-011,PROC-012,PROC-015';c='access';b='egressing process performs sensitive process access, injection, memory load, or dump';g='Distinct access, injection, assembly, library and dump signals are conflated; access mask and target sensitivity are not required';s='network-active process obtains dangerous rights to a protected process';t='split'},
 @{n='sliver_process_behavior_cluster';p='PROC-001';c='none';b='new process begins outbound communication';g='This behavior is ubiquitous and lacks first-seen image, destination reputation, signer, persistence, recurrence, or sensitive follow-on effects';s='rare unsigned process establishes first-seen external egress and recurs';t='rewrite'},
 @{n='sliver_recurrent_process_egress';p='PROC-002,PROC-003';c='beacon';b='one process repeatedly communicates outbound';g='Five connections is a weak count, missing periodicity, destination stability, rarity, long-lived flow and proxy visibility';s='low-jitter recurrent egress to a rare destination by one process';t='rewrite'},
 @{n='sliver_registry_from_network_process';p='PROC-018';c='registry';b='network-active process mutates registry state';g='Any registry mutation is too broad; security-sensitive keys, before/after value, persistence effect and process entity join are missing';s='network-active process writes a sensitive persistence or security-control key';t='patch'},
 @{n='sliver_remote_admin_sequence';p='PROC-020';c='remote';b='remote authentication is followed by service or SSH execution';g='Host and user joins can associate unrelated administration; stable logon/session identity, source continuity and created process are absent';s='remote session identifier joined to service/SSH execution and resulting child';t='rewrite'},
 @{n='sliver_screen_capture_process_egress';p='PROC-014';c='screen';b='screen-capture API activity is followed by same-process egress';g='Capture telemetry is tenant-normalized and may not identify the captured desktop, result artifact, session or API provider';s='screen-capture event joined by process entity to external transfer';t='patch'},
 @{n='sliver_server_control_plane_change';p='PROC-023,PROC-024';c='none';b='server audit records listener, staging, build, loot, credential, or task changes';g='One broad event class gives equal weight to benign administration and credential/loot actions; actor, approval, object and multi-host effects are absent';s='authenticated server audit action on a high-risk object by an unapproved actor';t='split'}
)
$d = @($d | Where-Object n -ne 'sliver_server_control_plane_change')
function Get-ProposalBody($name) {
 switch ($name) {
 'sliver_browser_debugging_from_network_process' { @'
    $p.metadata.event_type = "PROCESS_LAUNCH"
    $p.principal.process.pid = $parent_pid
    $p.target.process.pid = $browser_pid
    $p.target.process.command_line = /(?i)--remote-debugging-(port|pipe)/
    $l.metadata.event_type = "NETWORK_CONNECTION"
    $l.principal.process.pid = $browser_pid
    $l.network.direction = "LISTENING"
    $l.target.port = $debug_port
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.process.pid = $parent_pid
    $n.network.direction = "OUTBOUND"
    $p.metadata.event_timestamp.seconds <= $l.metadata.event_timestamp.seconds
  match:
    $parent_pid, $browser_pid over 5m
  condition:
    $p and $l and $n
'@ }
 'sliver_cleanup_after_egress' { @'
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.process.file.sha256 = $hash
    $n.principal.process.pid = $pid
    $n.network.direction = "OUTBOUND"
    $d.metadata.event_type = "FILE_DELETION"
    $d.principal.process.pid = $pid
    $d.target.file.sha256 = $hash
    $n.metadata.event_timestamp.seconds <= $d.metadata.event_timestamp.seconds
  match:
    $pid, $hash over 30m
  condition:
    $n and $d
'@ }
 'sliver_dns_or_udp_process_egress' { @'
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.principal.process.pid = $pid
    $e.network.ip_protocol = "UDP"
    $e.network.direction = "OUTBOUND"
    $e.target.ip = $destination
    $e.target.port = $port
    $e.target.resource.attribute.labels["destination_prevalence"] = "rare"
  match:
    $pid, $destination, $port over 30m
  outcome:
    $connections = count($e.metadata.id)
  condition:
    $e and $connections >= 6
'@ }
 'sliver_file_activity_from_network_process' { @'
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.process.pid = $pid
    $n.network.direction = "OUTBOUND"
    $f.metadata.event_type = /FILE_READ|FILE_CREATION|FILE_MODIFICATION|FILE_DELETION/
    $f.principal.process.pid = $pid
    $f.target.file.full_path = /(?i)(\\Windows\\System32\\config\\(SAM|SECURITY|SYSTEM)|ntds\.dit|\\Users\\[^\\]+\\AppData\\.*(Login Data|Cookies))/
  match:
    $pid over 15m
  condition:
    $n and $f
'@ }
 'sliver_identity_or_service_from_network_process' { @'
    $c.metadata.product_event_type = "4648"
    $c.principal.process.pid = $pid
    $c.principal.user.userid = $actor
    $c.target.user.userid = $credential_user
    $s.metadata.product_event_type = /4697|7045/
    $s.principal.user.userid = $credential_user
    $s.target.hostname = $host
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.process.pid = $pid
    $c.metadata.event_timestamp.seconds <= $s.metadata.event_timestamp.seconds
  match:
    $pid, $credential_user, $host over 10m
  condition:
    $c and $s and $n
'@ }
 'sliver_listener_with_egress' { @'
    $l.metadata.event_type = "NETWORK_CONNECTION"
    $l.principal.process.pid = $pid
    $l.principal.hostname = $host
    $l.network.direction = "INBOUND"
    $l.security_result.action = "ALLOW"
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.process.pid = $pid
    $n.principal.hostname = $host
    $n.network.direction = "OUTBOUND"
    $n.target.ip = $destination
    $n.target.resource.attribute.labels["destination_prevalence"] = "rare"
  match:
    $host, $pid over 10m
  condition:
    $l and $n
'@ }
 'sliver_parent_egress_with_spawned_interpreter' { @'
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.process.pid = $parent_pid
    $n.network.direction = "OUTBOUND"
    $p.metadata.event_type = "PROCESS_LAUNCH"
    $p.principal.process.pid = $parent_pid
    $p.target.process.pid = $child_pid
    $p.target.process.file.full_path = /(?i)(cmd|powershell|pwsh|sh|bash|zsh)(\.exe)?$/
    $n.metadata.event_timestamp.seconds <= $p.metadata.event_timestamp.seconds
  match:
    $parent_pid, $child_pid over 10m
  condition:
    $n and $p
'@ }
 'sliver_process_access_from_network_process' { @'
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.process.pid = $pid
    $n.network.direction = "OUTBOUND"
    $a.metadata.product_event_type = "10"
    $a.principal.process.pid = $pid
    $a.target.process.file.full_path = /(?i)\\(lsass|winlogon|csrss)\.exe$/
    $a.target.process.access_mask = /(?i)(0x1fffff|0x1f0fff|0x143a|0x1010)/
  match:
    $pid over 10m
  condition:
    $n and $a
'@ }
 'sliver_process_behavior_cluster' { @'
    $p.metadata.event_type = "PROCESS_LAUNCH"
    $p.target.process.pid = $pid
    $p.target.process.file.signature_info.verification_status != "VERIFIED"
    $p.target.process.file.full_path = $image
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.process.pid = $pid
    $n.network.direction = "OUTBOUND"
    $n.target.ip = $destination
    $n.target.resource.attribute.labels["destination_prevalence"] = "rare"
  match:
    $pid, $image, $destination over 15m
  condition:
    $p and $n
'@ }
 'sliver_recurrent_process_egress' { @'
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.principal.process.pid = $pid
    $e.network.direction = "OUTBOUND"
    $e.target.ip = $destination
    $e.target.resource.attribute.labels["destination_prevalence"] = "rare"
  match:
    $pid, $destination over 1h
  outcome:
    $connections = count($e.metadata.id)
    $active_minutes = count_distinct(timestamp.get_minute($e.metadata.event_timestamp.seconds))
  condition:
    $e and $connections >= 6 and $active_minutes >= 4
'@ }
 'sliver_registry_from_network_process' { @'
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.process.pid = $pid
    $n.network.direction = "OUTBOUND"
    $r.metadata.event_type = "REGISTRY_MODIFICATION"
    $r.principal.process.pid = $pid
    $r.target.registry.registry_key = /(?i)\\(Run|RunOnce|Services|Winlogon|Image File Execution Options|Terminal Server)\\?/
  match:
    $pid over 15m
  condition:
    $n and $r
'@ }
 'sliver_remote_admin_sequence' { @'
    $l.metadata.product_event_type = /4624|sshd_auth_success/
    $l.principal.ip = $source
    $l.target.hostname = $host
    $l.target.user.userid = $user
    $l.network.session_id = $session
    $x.metadata.product_event_type = /4697|7045|sshd_command/
    $x.principal.user.userid = $user
    $x.target.hostname = $host
    $x.network.session_id = $session
    $l.metadata.event_timestamp.seconds <= $x.metadata.event_timestamp.seconds
  match:
    $source, $host, $user, $session over 10m
  condition:
    $l and $x
'@ }
 'sliver_screen_capture_process_egress' { @'
    $c.metadata.product_event_type = /SCREEN_CAPTURE|DesktopDuplication|BitBlt/
    $c.principal.process.pid = $pid
    $c.principal.hostname = $host
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.process.pid = $pid
    $n.principal.hostname = $host
    $n.network.direction = "OUTBOUND"
    $c.metadata.event_timestamp.seconds <= $n.metadata.event_timestamp.seconds
  match:
    $host, $pid over 5m
  condition:
    $c and $n
'@ }
 'sliver_server_control_plane_change' { @'
    $e.metadata.product_name = "Sliver Server Audit"
    $e.metadata.event_type = "USER_RESOURCE_ACCESS"
    $e.security_result.action = "ALLOW"
    $e.principal.user.userid = $operator
    $e.target.resource.resource_type = /(?i)(credential|loot|listener|stager|build|task)/
    $e.target.resource.attribute.labels["approved_change"] = "false"
  match:
    $operator over 10m
  condition:
    $e
'@ }
 default { throw "No proposal body for $name" }
 }
}
$out=Join-Path $root 'public-rules/comparisons/sliver'; New-Item -ItemType Directory -Force $out|Out-Null
foreach($x in $d){
 $ir="detections/sliver/yaral/$($x.n).yaral"; $pp=$pub[$x.c]
 $ih=(Get-FileHash (Join-Path $root $ir) -Algorithm SHA256).Hash.ToLowerInvariant()
 if($x.c -eq 'none') {
   $candidateBlock='- No credible behaviorally comparable public rule was found in the pinned corpus; candidate evidence status: `insufficient_evidence`.'
   $publicCoverage='No credible counterpart; not scored'
   $publicWeakness='No candidate was forced into this comparison. The pinned corpus provides insufficient evidence for a public-versus-internal branch conclusion.'
   $scopeConclusion='insufficient_evidence'
   $missingPublic='No public counterpart was identified, so public branch coverage is unknown rather than assumed absent.'
 } else {
   if(!(Test-Path (Join-Path $root $pp))){throw "Missing mapped public candidate: $pp"}
   $ph=(Get-FileHash (Join-Path $root $pp) -Algorithm SHA256).Hash.ToLowerInvariant()
   $link='../../'+($pp-replace '\\','/')
   $candidateBlock="- [``$pp``]($link) - SHA-256 ``$ph``"
   $publicCoverage='Overlapping behavior under candidate-specific assumptions'
   $publicWeakness='The candidate supplies useful behaviorally relevant telemetry but not the whole Sliver procedure. Backend assumptions and fixed thresholds are not tenant validation; its predicates must not be copied blindly.'
   $scopeConclusion='complementary'
   $missingPublic='The public candidate does not cover complete Sliver procedure ordering, the internal process-to-effect correlation, or tool-name-independent downstream confirmation.'
 }
 $body=Get-ProposalBody $x.n
 $code=@"
rule $($x.n)_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "$($x.p)"
    source_comparison = "unvalidated_proposal"
  events:
$body
}
"@
 $md=@"
# Public-rule comparison: $($x.n)

## Identity and independence gate

- Internal tool: ``sliver``
- Internal canonical rule: ``$ir``
- Internal SHA-256: ``$ih``
- Internal review completed before public comparison: ``yes``
- Procedure IDs: ``$($x.p)``
- Scope mapping rationale: procedure, ordered behavior, security effect, platform and telemetry; names and syntax were not mapping criteria.

Public candidate:
$candidateBlock

## Procedure and detection-branch matrix

| Procedure branch / effect | Ours | Public | Primary signal and strength | Compensating signal | Conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Process/session prerequisite | Partial process or identity context | Adjacent behavior only | Stable process/session entity - moderate | signer, first-seen and host-role context | complementary | Internal ``$($x.p)`` inventory; cited candidate. |
| $($x.b) | Principal event family covered | $publicCoverage | $($x.s) - strong | ordered child/file/network/state effect - moderate | $scopeConclusion | Security effect is closer to procedure than a tool name. |
| Result, recurrence or cleanup | Partial or absent | Partial or outside scope | Verified resulting state - strong | subsequent access, transfer, deletion or authentication - moderate | different_scope | Neither rule closes every downstream branch. |

## Missing detection branches

- Missing from ours: $($x.g).
- Missing from public: $missingPublic
- Missing from both: activity split across processes/hosts, low-and-slow execution, encrypted application content, telemetry outages, and reliable confirmation of operator intent.

## Detection edge cases and blind spots

Process identifiers can be reused and differ across sensors; prefer a sensor-issued process entity ID when available. NAT, proxies, resolver infrastructure, delayed ingestion, clock skew and partial endpoint visibility can break ordering. Legitimate software deployment, remote support, browsers, proxies, backup, monitoring and administration overlap with individual primitives. Baselines should raise or lower confidence without excluding the sensitive effect. Distributed and low-rate activity needs longer-lived entity analytics rather than simply expanding every correlation window.

## Signal-quality assessment

| Signal | Strength | Used by | Reason | Fragility |
| --- | --- | --- | --- | --- |
| $($x.s) | strong | proposed refinement | Close to the security effect and behavior-based. | Requires stable entity joins and declared telemetry. |
| Process-attributed egress | moderate | ours | Valuable causal context but common alone. | Proxying and sensor gaps reduce attribution. |
| Image, argument, port or default name | weak | some public logic | Useful enrichment, not durable intent. | Mutable and common in benign workloads. |

## Public-rule weaknesses

$publicWeakness

## Internal-rule weaknesses

$($x.g). Broad joins risk benign collisions; narrow windows and same-process assumptions risk false negatives during delayed, delegated or distributed behavior.

## Decision trail

- Candidate improvement: independently implement and test the strong branch below.
- Independent verification: pinned Sliver source, provider semantics, schema mappings and authorized sanitized fixtures required.
- Decision: ``deferred_pending_rule_improvement_run``
- Reason: comparative evidence is not canonical authority; proposal has not passed adversarial review.
- Required regeneration: canonical detection review, coverage, telemetry/master, five translations, dependencies/manifests/hashes, then re-comparison.

## Unmatched scope

The candidate does not cover all of ``$($x.p)``. No global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: ``$($x.t)``
- Addresses branches: $($x.g).
- Required telemetry: stable process/session entity, actor, host, event time, action/result and procedure-specific file/network/state fields.
- Validation status: ``unvalidated_proposal``

``````yaral
$code
``````

The proposal uses concrete telemetry semantics but does not prove tool identity. It remains limited by collection health, process-entity fidelity, enrichment quality and activity outside the window. If accepted or modified, complete the full downstream workflow; if rejected, preserve the rationale without changing canonical logic.
"@
 Set-Content (Join-Path $out "$($x.n).md") $md -Encoding utf8
}
$rows=$d|%{"| [``$($_.n)``](./$($_.n).md) | ``$($_.p)`` | $($_.t) | deferred_pending_rule_improvement_run |"}
$idx=@"
# Sliver public-rule comparison index

All 14 canonical Sliver rules have threat-detection comparisons. Public rules are untrusted comparative inputs; every YARA-L block is an ``unvalidated_proposal`` and canonical logic was not changed.

| Internal rule | Procedures | Proposal | Decision |
| --- | --- | --- | --- |
$($rows-join "`n")

## Portfolio findings

- Internal rules benefit from process-attributed network correlation, but many joins need sensor-issued process/session identity rather than PID, host or account alone.
- Weak recurring branches include raw connection counts, broad file/registry activity and conflated identity/service/process-access signals.
- Stronger coverage requires verified security effects, procedure-specific splits, first-seen/role context and collection-health awareness.
- Public candidates provide useful adjacent signals but do not establish complete Sliver procedures or justify blind predicate adoption.
"@
Set-Content (Join-Path $out 'INDEX.md') $idx -Encoding utf8
