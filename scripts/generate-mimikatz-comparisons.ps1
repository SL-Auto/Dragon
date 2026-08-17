$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$out=Join-Path $root 'public-rules/comparisons/mimikatz'
New-Item -ItemType Directory -Force -Path $out|Out-Null
$rev='7e91c156324cdc64cda27f7fec7067b1148074ef'
$pub=@{
 lsass=@('credential_access_lsass_openprocess_api.toml','b053c9ff7abe3db0852a2d05888838aae2c514b32dd028624cad9964b940ce89','LSASS OpenProcess API access')
 dcsync=@('credential_access_dcsync_replication_rights.toml','4ebde964c7eccf61c3b015ebaebab06e7d5f0f7b8031e57b0135d727cc71066b','directory replication-right access')
 dpapi=@('credential_access_domain_backup_dpapi_private_keys.toml','b69707ba64c8a361e1ca8834e3bb0ff0f970c9e5eab4ae3e61f7cbf63a1e43ae','DPAPI domain backup-key access')
 ticket=@('credential_access_kirbi_file.toml','6456b8900761c8253414fcd3b06d1eb2d57255d1a88ee8712b53b4ddd5a7c1e8','Kerberos ticket artifact creation')
 inject=@('defense_evasion_posh_process_injection.toml','f9437046f997f6c05a9b68a28de50d5a180615046bdfc62d8cc5ddc5188c5f16','PowerShell process injection')
 token=@('privilege_escalation_tokenmanip_sedebugpriv_enabled.toml','66429a12ee26c63892341e2f91d2b7c171da9ad9f30fabd2ac613e5a069d5b6d','SeDebugPrivilege enablement')
 ssp=@('persistence_via_lsa_security_support_provider_registry.toml','49cfe6d605473eedb20f48f0d285a100081ea4f3f91bcc9f3e21cf02a47410a6','LSA security-package registration')
 hive=@('credential_access_moving_registry_hive_via_smb.toml','8d2a3185916669a3978e98eebfe9f2919f6c72960cd97f985856d819bc2db741','protected hive movement')
 pth=@('lateral_movement_alternate_creds_pth.toml','c97393830fa3ec379bd46076c8f75be58db509c63c1d5661ef5f976d5f40f43b','alternate-credential lateral movement')
}
$D=@(
@{n='mimikatz_account_secret_change';p='P16';c='pth';b='SAMR or Netlogon changes a machine/account secret';o='secret-change events across multiple accounts';u='remote password resets and credential use, but not protocol-level secret change';g='single high-value account, protocol result, caller trust and subsequent authentication';s='successful secret change by a non-management caller with later authentication';w='generic password reset';v='ours_stronger';t='rewrite';pr='mimikatz_untrusted_account_secret_change';e='$e.metadata.product_event_type = /(4723|4724|NETLOGON_SECRET_CHANGE|SAMR_PASSWORD_SET)/`n    $e.principal.user.userid = $actor`n    $e.target.user.userid = $account`n    $e.security_result.action = "ALLOW"`n    $e.principal.labels["approved_password_manager"] = "false"';m='$actor over 30m';o2='$accounts = count_distinct($account)';co='$e and $accounts >= 2';rq='successful SAMR/Netlogon or Windows password-change events with actor, target and approved-management enrichment'}
@{n='mimikatz_certificate_key_operation';p='P21,P24';c='dpapi';b='certificate enrollment or Hello key material is exported, moved or accessed';o='certificate/key operation activity';u='DPAPI backup-key access only';g='private-key export result, key provider, caller process, Hello container access';s='successful non-exportable private-key export or NGC key-container read by an untrusted process';w='certificate API use';v='ours_stronger';t='compensating_rule';pr='mimikatz_private_key_export_or_ngc_access';e='$e.metadata.product_event_type = /(CAPI2_KEY_EXPORT|NGC_KEY_ACCESS|CRYPTO_KEY_EXPORT)/`n    $e.principal.process.file.labels["trusted_key_manager"] = "false"`n    $e.target.resource.attribute.labels["key_exportable"] = "false"`n    $e.security_result.action = "ALLOW"';m='$e.principal.hostname over 15m';o2='$operations = count($e.metadata.id)';co='$e and $operations >= 1';rq='CAPI2/crypto provider and NGC key access with export result, key properties and caller process trust'}
@{n='mimikatz_clipboard_device_access';p='P34,P42';c='inject';b='clipboard or hardware device content is accessed for collection/control';o='device/clipboard access context';u='process injection only';g='clipboard read APIs, raw device handle access, caller trust';s='rare process repeatedly reading clipboard or protected device objects';w='clipboard API access alone';v='different_scope';t='split';pr='mimikatz_untrusted_clipboard_collection';e='$e.metadata.product_event_type = "CLIPBOARD_READ"`n    $e.principal.process.product_specific_process_id = $pid`n    $e.principal.process.file.labels["approved_clipboard_app"] = "false"`n    $e.target.resource.attribute.labels["content_present"] = "true"';m='$e.principal.hostname, $pid over 10m';o2='$reads = count($e.metadata.id)';co='$e and $reads >= 3';rq='EDR clipboard-read or API telemetry with process entity, content-present flag and approved application enrichment'}
@{n='mimikatz_cross_process_tamper';p='P22,P27,P28,P32,P40';c='inject';b='a process opens, writes, injects into or tampers with another security-sensitive process';o='cross-process access/tamper correlation';u='PowerShell-specific injection sequence';g='non-PowerShell injection, memory protection changes, sensitive target classes and remote thread creation';s='write/allocate/protect/thread sequence against a sensitive target';w='one cross-process handle open';v='complementary';t='rewrite';pr='mimikatz_cross_process_write_execute_sequence';e='$a.metadata.product_event_type = /(PROCESS_OPEN|VIRTUAL_ALLOC_EX)/`n    $a.principal.process.product_specific_process_id = $source`n    $a.target.process.product_specific_process_id = $target`n    $w.metadata.product_event_type = /(WRITE_PROCESS_MEMORY|CREATE_REMOTE_THREAD|QUEUE_APC)/`n    $w.principal.process.product_specific_process_id = $source`n    $w.target.process.product_specific_process_id = $target`n    $w.target.process.file.labels["security_sensitive"] = "true"';m='$source, $target over 5m';o2='$stages = count_distinct($w.metadata.product_event_type)';co='$a and $w';rq='EDR cross-process allocation/write/thread events with stable source/target process entities and sensitive-target classification'}
@{n='mimikatz_directory_mutation';p='P15,P29';c='dcsync';b='DCShadow-like directory registration/write or SID-history mutation changes AD state';o='directory mutation events and replication context';u='replication-right reads, not object mutation';g='rogue replication registration, SPN/object writes, SID-history change and authoritative result';s='successful replication-related directory mutation by a non-DC identity';w='generic 5136 modification';v='ours_stronger';t='rewrite';pr='mimikatz_rogue_replication_directory_mutation';e='$e.metadata.product_event_type = /(5136|4742|DIRECTORY_OBJECT_MODIFY)/`n    $e.principal.user.userid = $actor`n    $e.principal.labels["is_domain_controller"] = "false"`n    re.regex($e.target.resource.attribute.labels["changed_attribute"], `(?i)(servicePrincipalName|msDS-AdditionalDnsHostName|sIDHistory)`)`n    $e.security_result.action = "ALLOW"';m='$actor over 20m';o2='$attributes = count_distinct($e.target.resource.attribute.labels["changed_attribute"])';co='$e and $attributes >= 1';rq='resolved directory modifications with actor, changed attribute/value class, result and DC-identity enrichment'}
@{n='mimikatz_directory_network_discovery';p='P30';c='dcsync';b='domain, DC, trust and network topology are enumerated';o='directory/network discovery breadth';u='replication-right access only';g='single-category deep discovery, DNS/SRV queries, trust enumeration and slow activity';s='same process combines DC/trust discovery with sensitive follow-on operation';w='ordinary LDAP or DNS lookup';v='different_scope';t='compensating_rule';pr='mimikatz_domain_discovery_to_sensitive_access';e='$d.metadata.product_event_type = /(LDAP_SEARCH|DNS_QUERY|DOMAIN_DISCOVERY)/`n    $d.principal.process.product_specific_process_id = $pid`n    $d.target.resource.attribute.labels["discovery_family"] = $family`n    $s.metadata.product_event_type = /(PROCESS_OPEN|DIRECTORY_REPLICATION_ACCESS|REGISTRY_READ)/`n    $s.principal.process.product_specific_process_id = $pid`n    $s.target.resource.attribute.labels["security_sensitive"] = "true"';m='$pid over 30m';o2='$families = count_distinct($family)';co='$families >= 2 and $s';rq='process-attributed DNS/LDAP/domain discovery plus sensitive process/directory/registry access'}
@{n='mimikatz_directory_replication_right_access';p='P14';c='dcsync';b='a non-DC principal requests directory replication rights';o='replication access-right GUIDs with source/account context';u='same DCSync security effect using Elastic field mappings';g='single-object targeted replication, RPC network context, DC allowlist health and identity normalization';s='successful replication-right access by a non-DC machine/account';w='4662 without property GUID resolution';v='equivalent';t='rewrite';pr='mimikatz_non_dc_replication_right_access';e='$e.metadata.product_event_type = /(4662|DIRECTORY_REPLICATION_ACCESS)/`n    $e.principal.user.userid = $actor`n    $e.principal.labels["is_domain_controller"] = "false"`n    $e.target.resource.attribute.labels["access_right"] = /(?i)(DS-Replication-Get-Changes|DS-Replication-Get-Changes-All|DS-Replication-Get-Changes-In-Filtered-Set)/`n    $e.security_result.action = "ALLOW"';m='$actor over 10m';o2='$rights = count_distinct($e.target.resource.attribute.labels["access_right"])';co='$e and $rights >= 2';rq='4662 with resolved replication-right GUIDs, actor machine/account normalization, result and authoritative DC inventory'}
@{n='mimikatz_event_log_impairment';p='P26';c='inject';b='Windows event channels are cleared, disabled or logging state is impaired';o='event-log impairment operations';u='injection, not log-service state';g='channel configuration changes, service stop, audit-policy change and collection-health loss';s='successful audit/log channel disable or clear plus collector health change';w='process command line mentioning logs';v='ours_stronger';t='compensating_rule';pr='mimikatz_event_channel_impairment_with_health';e='$e.metadata.product_event_type = /(1102|104|EVENT_CHANNEL_CONFIG_CHANGE|AUDIT_POLICY_CHANGE)/`n    $e.principal.user.userid = $actor`n    $e.security_result.action = "ALLOW"`n    $e.target.resource.attribute.labels["logging_enabled"] = "false"';m='$actor over 15m';o2='$channels = count_distinct($e.target.resource.name)';co='$e and $channels >= 1';rq='Security/System log clear, channel configuration and audit-policy events with actor/result plus collector-health monitoring'}
@{n='mimikatz_firmware_driver_operation';p='P39,P43';c='ssp';b='firmware variables or a kernel driver expose privileged memory/hardware operations';o='driver/firmware operation context';u='LSA package persistence only';g='driver load trust, vulnerable-driver identity, firmware write result and subsequent device access';s='untrusted driver load followed by privileged device or firmware variable operation';w='driver filename or service creation alone';v='different_scope';t='rewrite';pr='mimikatz_driver_to_privileged_device_operation';e='$d.metadata.product_event_type = /(6|DRIVER_LOAD)/`n    $d.principal.hostname = $host`n    $d.target.file.labels["trusted_driver"] = "false"`n    $d.target.file.sha256 = $driver`n    $o.metadata.product_event_type = /(FIRMWARE_VARIABLE_WRITE|DEVICE_IO_CONTROL|PHYSICAL_MEMORY_ACCESS)/`n    $o.principal.hostname = $host`n    $o.principal.process.file.sha256 = $driver';m='$host, $driver over 20m';o2='$operations = count($o.metadata.id)';co='$d and $o';rq='driver load/signature telemetry plus firmware/device/physical-memory operations correlated by driver identity'}
@{n='mimikatz_kerberos_activity';p='P10';c='ticket';b='Kerberos cache tickets are listed, exported, purged or submitted';o='cache/API and ticket artifact behavior';u='kirbi file creation only';g='LSA ticket submit/retrieve, cache purge, ticket use after submission and in-memory-only operations';s='caller-attributed LSA ticket submission followed by use';w='kirbi extension alone';v='complementary';t='rewrite';pr='mimikatz_ticket_submission_and_use';e='$s.metadata.product_event_type = "LSA_KERBEROS_TICKET_SUBMIT"`n    $s.principal.user.userid = $user`n    $s.principal.process.product_specific_process_id = $pid`n    $s.target.resource.attribute.labels["logon_id"] = $luid`n    $u.metadata.product_event_type = /(4769|KERBEROS_SERVICE_AUTH)/`n    $u.principal.user.userid = $user`n    $u.principal.resource.attribute.labels["logon_id"] = $luid';m='$user, $luid over 30m';o2='$services = count_distinct($u.target.resource.name)';co='$s and $u';rq='caller-attributed LSA Kerberos package operations and subsequent Kerberos authentication joined by logon session'}
@{n='mimikatz_lsass_memory_access';p='P07,P09,P13';c='lsass';b='LSASS is opened/read/dumped or modified for credentials/authentication state';o='LSASS handle/API access and access rights';u='OpenProcess API access with suspicious caller/access';g='direct syscalls, PPL bypass, cloned/snapshot LSASS, read versus write distinction and downstream dump/use';s='untrusted caller obtains read/write access to LSASS with result and call stack';w='PROCESS_OPEN without granted access/result';v='complementary';t='rewrite';pr='mimikatz_lsass_sensitive_granted_access';e='$e.metadata.product_event_type = /(PROCESS_OPEN|PROCESS_ACCESS)/`n    $e.target.process.file.full_path = /(?i)\\lsass\.exe$/`n    $e.principal.process.file.labels["trusted_lsass_accessor"] = "false"`n    $e.security_result.action = "ALLOW"`n    $e.target.process.attribute.labels["granted_access"] = /(?i)(VM_READ|VM_WRITE|VM_OPERATION|CREATE_THREAD)/';m='$e.principal.hostname, $e.principal.process.product_specific_process_id over 5m';o2='$rights = count_distinct($e.target.process.attribute.labels["granted_access"])';co='$e and $rights >= 1';rq='EDR process access with granted rights, success, source/target process entity, signer and call-stack/trust enrichment'}
@{n='mimikatz_process_file_context';p='P01,P31,P33';c='hive';b='utility execution, spawned tools and transformed/staged output create process/file context';o='process plus file lifecycle correlation';u='protected hive movement only';g='memory-only operation, renamed utilities, stdout output, service execution and non-default staging paths';s='untrusted process creates multiple sensitive credential/ticket/hive artifact classes';w='filename or command keyword';v='complementary';t='compensating_rule';pr='mimikatz_sensitive_artifact_fanout';e='$e.metadata.product_event_type = /(11|FILE_CREATION)/`n    $e.principal.process.product_specific_process_id = $pid`n    $e.target.file.labels["sensitive_artifact_class"] = $class`n    $e.principal.process.file.labels["approved_credential_tool"] = "false"';m='$e.principal.hostname, $pid over 20m';o2='$classes = count_distinct($class)';co='$e and $classes >= 2';rq='process-attributed file creation with enrichment for hive, dump, ticket, key and credential-output artifact classes'}
@{n='mimikatz_protected_sam_system_access_sequence';p='P12';c='hive';b='SAM and SYSTEM/SECURITY protected hives are accessed or staged together';o='ordered protected-hive access sequence';u='hive transfer over SMB';g='VSS/raw-volume access, registry save APIs, one hive plus boot key, alternate paths and delayed staging';s='same process reads complementary protected hives or snapshot copies';w='single hive filename';v='ours_stronger';t='rewrite';pr='mimikatz_complementary_protected_hive_access';e='$e.metadata.product_event_type = /(REGISTRY_HIVE_SAVE|FILE_READ|RAW_VOLUME_READ)/`n    $e.principal.process.product_specific_process_id = $pid`n    $e.target.file.labels["protected_hive"] = $hive`n    $hive = /(?i)(SAM|SYSTEM|SECURITY)/`n    $e.principal.process.file.labels["approved_backup"] = "false"';m='$e.principal.hostname, $pid over 30m';o2='$hives = count_distinct($hive)';co='$e and $hives >= 2';rq='registry hive save, snapshot/raw-volume or file reads with resolved hive identity and source process trust'}
@{n='mimikatz_rpc_pipe_activity';p='P35,P38';c='pth';b='named-pipe/RPC control or forced-authentication procedure is invoked';o='pipe/RPC operation correlation';u='credentialed lateral movement rather than coercion/control';g='interface UUID/opnum, pipe creation/access direction, target identity, result and subsequent authentication';s='resolved coercion RPC operation followed by target authentication to caller-controlled endpoint';w='named pipe string alone';v='different_scope';t='rewrite';pr='mimikatz_rpc_coercion_to_authentication';e='$r.metadata.product_event_type = "RPC_CALL"`n    $r.principal.hostname = $source`n    $r.target.hostname = $target`n    $r.target.resource.attribute.labels["rpc_operation_class"] = "authentication_coercion"`n    $a.metadata.product_event_type = /(NTLM_AUTH|KERBEROS_AUTH)/`n    $a.principal.hostname = $target`n    $a.target.hostname = $destination';m='$target over 5m';o2='$destinations = count_distinct($destination)';co='$r and $a';rq='resolved RPC interface/operation plus network authentication events joined by coerced target and time'}
@{n='mimikatz_sensitive_store_access';p='P18,P19,P20,P23,P25,P37,P41,P46';c='dpapi';b='credential managers, DPAPI stores, Vault, browser/app or protected key stores are read/exported';o='broad sensitive-store access';u='domain DPAPI backup-key access';g='store-specific APIs, result, caller process, multiple store families and local versus domain key paths';s='untrusted process successfully accesses multiple independent credential-store families';w='one file/registry path read';v='complementary';t='rewrite';pr='mimikatz_multi_store_credential_access';e='$e.metadata.product_event_type = /(CREDENTIAL_STORE_ACCESS|FILE_READ|REGISTRY_READ|DPAPI_KEY_ACCESS)/`n    $e.principal.process.product_specific_process_id = $pid`n    $e.target.resource.attribute.labels["credential_store_family"] = $store`n    $e.security_result.action = "ALLOW"`n    $e.principal.process.file.labels["approved_credential_manager"] = "false"';m='$e.principal.hostname, $pid over 20m';o2='$stores = count_distinct($store)';co='$e and $stores >= 2';rq='store/API-specific access with result, stable process entity and normalized credential-store family'}
@{n='mimikatz_service_driver_module_change';p='P06,P36,P44,P45';c='ssp';b='service, driver, print monitor or LSA module state is changed';o='service/module change correlation';u='specific security-package registry persistence';g='print monitor, service DLL, driver load result, module load into LSASS/spooler and signer trust';s='untrusted module registration followed by load into a protected service process';w='7045 service install alone';v='complementary';t='rewrite';pr='mimikatz_module_registration_to_protected_load';e='$r.metadata.product_event_type = /(4657|REGISTRY_VALUE_SET|7045)/`n    $r.principal.hostname = $host`n    $r.target.file.full_path = $module`n    $l.metadata.product_event_type = /(7|IMAGE_LOAD)/`n    $l.principal.hostname = $host`n    $l.target.file.full_path = $module`n    $l.principal.process.file.full_path = /(?i)(lsass|spoolsv)\.exe$/`n    $l.target.file.labels["trusted_module"] = "false"';m='$host, $module over 30m';o2='$loads = count($l.metadata.id)';co='$r and $l';rq='registry/service/module registration plus image-load telemetry with normalized module path, target process and signature trust'}
@{n='mimikatz_token_process_control';p='P02,P03,P04,P05';c='token';b='privileges, tokens and process state are enumerated or manipulated';o='privilege/token/process control correlation';u='SeDebugPrivilege enablement';g='token duplication/impersonation, target user, result, handle rights and subsequent sensitive access';s='SeDebug enablement or token impersonation followed by sensitive process access';w='privilege enablement alone';v='complementary';t='rewrite';pr='mimikatz_token_manipulation_to_sensitive_access';e='$t.metadata.product_event_type = /(PRIVILEGE_ENABLE|TOKEN_DUPLICATE|TOKEN_IMPERSONATE)/`n    $t.principal.hostname = $host`n    $t.principal.process.product_specific_process_id = $pid`n    $t.target.resource.attribute.labels["privilege_or_action"] = /(?i)(SeDebugPrivilege|duplicate|impersonate)/`n    $a.metadata.product_event_type = /(PROCESS_ACCESS|CREDENTIAL_STORE_ACCESS)/`n    $a.principal.hostname = $host`n    $a.principal.process.product_specific_process_id = $pid`n    $a.target.resource.attribute.labels["security_sensitive"] = "true"';m='$host, $pid over 10m';o2='$actions = count_distinct($t.target.resource.attribute.labels["privilege_or_action"])';co='$t and $a';rq='token/privilege operations and sensitive follow-on access tied by stable process entity'}
)
$rejectedCounterparts = @(
  'mimikatz_account_secret_change',
  'mimikatz_certificate_key_operation',
  'mimikatz_clipboard_device_access',
  'mimikatz_directory_mutation',
  'mimikatz_directory_network_discovery',
  'mimikatz_event_log_impairment',
  'mimikatz_firmware_driver_operation',
  'mimikatz_rpc_pipe_activity'
)
foreach($r in $D){
 if($r.n -in $rejectedCounterparts){
   $r.v='insufficient_evidence'
   $r.u="No credible public counterpart in the pinned corpus; the examined $($pub[$r.c][2]) rule is adjacent only and is rejected as a procedure comparator"
 }
 $candidateLabel = if($r.v -eq 'insufficient_evidence'){ 'Closest public rule examined and rejected as a counterpart' } else { 'Behaviorally relevant public candidate' }
 $ip="detections/mimikatz/yaral/$($r.n).yaral";$ih=(Get-FileHash (Join-Path $root $ip)-Algorithm SHA256).Hash.ToLower();$c=$pub[$r.c];$pp="public-rules/snapshots/elastic-security/$rev/rules/windows/$($c[0])";$rel='../../'+($pp-replace '^public-rules/','');$ev=$r.e-replace '`n',"`n"
 $matchExpr=$r.m.Replace('$e.principal.hostname','$host').Replace('$e.principal.process.product_specific_process_id','$pid')
 if($r.m -match '\$e\.principal\.hostname' -and $ev -notmatch '\$e\.principal\.hostname\s*=\s*\$host'){ $ev += "`n    `$e.principal.hostname = `$host" }
 if($r.m -match '\$e\.principal\.process\.product_specific_process_id' -and $ev -notmatch '\$e\.principal\.process\.product_specific_process_id\s*=\s*\$pid'){ $ev += "`n    `$e.principal.process.product_specific_process_id = `$pid" }
 $doc=@"
# Public-rule comparison: $($r.n)

## Identity and independence gate

- Internal tool: ``mimikatz``
- Internal canonical rule: ``$ip``
- Internal SHA-256: ``$ih``
- Internal review completed before public comparison: ``yes``
- Procedure IDs: ``$($r.p)``
- Scope mapping rationale: mapped by security effect, ordered procedure and required telemetry; names and syntax were not mapping criteria.

Public evidence:
- ${candidateLabel}: [$($c[2])]($rel) - pinned Elastic revision ``$rev``; SHA-256 ``$($c[1])``.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| $($r.b) | $($r.o) | $($r.u) | $($r.s) - strong | $($r.w) - weak | $($r.v) | Canonical rule, pinned candidate, ``coverage/mimikatz.yml`` and pinned source report. |
| Same effect split across processes, hosts or windows | Current joins/thresholds may fail | Public candidate is also bounded by its source | stable entity plus resulting security effect - moderate | longer-window rare relationship - moderate | insufficient_evidence | Analytical inference requiring local telemetry testing. |

## Missing detection branches

- Missing from ours: $($r.g).
- Missing from public rule: complete coverage of ``$($r.p)`` and alternate implementations outside its telemetry assumptions.
- Missing from both: intent attribution and reliable detection when the necessary provider is disabled or fields are dropped.

## Detection edge cases and blind spots

Low-and-slow and distributed activity may fall outside fixed windows. Identity, process and host entities can change representation between providers. Collection loss can suppress cardinality or break ordering. Legitimate administration and security products require evidence-based trust enrichment rather than path-only exclusions.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| $($r.s) | strong | proposed/internal | Close to the security effect and incorporates caller/result context. | Requires detailed provider fields and local baselining. |
| procedure-specific correlation | moderate | ours | Adds ordered context but depends on stable joins and windows. | Partial telemetry creates false negatives. |
| $($r.w) | weak | public/current branch | Useful triage lead but insufficient proof by itself. | Common, mutable or implementation-specific. |

## Public-rule weaknesses

$(if($r.v -eq 'insufficient_evidence'){ 'No credible public counterpart was found in the pinned corpus. The cited rule was inspected because it is adjacent in the attack chain, but it does not observe the same procedure or security effect and supplies no authority for changing our logic.' } else { 'The public candidate is a scoped compensating signal, not a full Mimikatz procedure model. Its fixed field assumptions and implementation focus can miss the same effect produced through a different API or telemetry path.' })

## Internal-rule weaknesses

$($r.g). Existing thresholds and normalized fields remain unvalidated hypotheses and require collection-health monitoring.

## Decision trail

- Candidate improvement: independently implement and validate the missing branch below; no upstream predicate is copied blindly.
- Independent verification: pinned source behavior, provider semantics, sanitized fixtures, benign baselines and adversarial detection review.
- Decision: ``deferred_pending_rule_improvement_run``.
- Reason: proposal is comparative evidence, not canonical authority.
- Required regeneration: internal review, coverage, telemetry/master counts, all translations, dependencies/hashes and refreshed comparison.

## Unmatched scope

The candidate does not cover every procedure branch. Conclusions are branch-scoped as ``$($r.v)`` or ``insufficient_evidence``; neither rule is claimed globally better.

## Proposed YARA-L improvement

- Change type: ``$($r.t)``
- Addresses branches: $($r.g).
- Required telemetry: $($r.rq).
- Validation status: ``unvalidated_proposal``

``````yaral
rule $($r.pr) {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "$($r.p)"
  events:
    $ev
  match:
    $matchExpr
  outcome:
    $($r.o2)
  condition:
    $($r.co)
}
``````

Remaining gaps: thresholds, fields, ordering and trust enrichment need authorized telemetry validation; absence of required collection cannot be interpreted as benign activity.

If accepted or modified, update canonical YARA-L and every downstream artifact, re-run adversarial review, and compare the revised final rule again.
"@
 Set-Content (Join-Path $out "$($r.n).md") $doc -Encoding utf8
}
$rows=$D|%{"| [$($_.n)](./$($_.n).md) | $($_.p) | $($_.v) | $($_.t) |"}
$idx=@"
# Mimikatz public-rule comparison index

Pinned Elastic revision: ``$rev``.

All 17 canonical Mimikatz rules were compared at procedure-branch and signal-strength level. Public rules are independent evidence only; proposed code remains ``unvalidated_proposal`` and canonical detections were not changed.

| Internal rule | Procedures | Headline conclusion | Proposed change |
| --- | --- | --- | --- |
$($rows -join "`n")

## Cross-rule findings

- Strong signals are successful LSASS/replication/key/store operations, resolved cross-process writes, protected-state mutations and resulting authentication or module-load effects.
- Weak signals are filenames, command fragments, generic process opens, service installs and single path reads without result or caller context.
- Recurring internal gaps are stable entity joins, explicit success/granted rights, non-default APIs, distributed activity and authoritative trust/collection-health enrichment.
- Public coverage is strongest for LSASS access, DCSync, DPAPI backup keys, ticket artifacts, SeDebug, hive movement and LSA packages; it is sparse for several RPC, firmware, clipboard and multi-store branches.

## Review status

Threat-detection comparison complete for 17/17 rules with concrete YARA-L proposals. Adoption remains a separate canonical improvement workflow.
"@
Set-Content (Join-Path $out 'INDEX.md') $idx -Encoding utf8
