$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$chron = 'public-rules/snapshots/chronicle-community/234e9223c3b8f3d1c30209d9663797ba69057533'
$elastic = 'public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef'
$candidates = @{
  service = "$chron/rules-community/microsoft/windows/win_susp_or_malicious_service_created.yaral"
  task = "$chron/rules-community/microsoft/windows/mitre_attack_T1053_005_windows_creation_of_scheduled_task.yaral"
  wmi = "$chron/rules-community/microsoft/windows/impacket_wmiexec_cisa_report.yaral"
  account = "$chron/rules-community/microsoft/windows/win_short_term_account_use.yaral"
  registry = "$chron/rules-community/microsoft/windows/potential_tampering_with_rdp_related_registry_keys_via_reg_exe.yaral"
  smb = "$elastic/rules/network/initial_access_smb_windows_file_sharing_activity_from_the_internet.toml"
  rpc = "$elastic/rules/network/initial_access_rpc_remote_procedure_call_from_the_internet.toml"
  packet = "$elastic/rules/integrations/azure/credential_access_network_full_network_packet_capture_detected.toml"
  kerberos = "$elastic/rules/_deprecated/privilege_escalation_krbrelayup_suspicious_logon.toml"
}
$data = @(
  @{n='impacket_ad_authorization_change'; p='IMP-10'; c='account'; branch='security-descriptor, ownership, delegation and dMSA authorization mutation'; missing='Attribute-specific before/after interpretation and correlation to the initiating network session'; signal='5136/5137 on a protected object with a security-sensitive attribute'; event='/(5136|5137)/'; extra='$e.target.resource.attribute.labels["sensitive_ad_attribute"] = "true"'; type='patch'},
  @{n='impacket_cross_source_ntlm_relay'; p='IMP-21'; c='kerberos'; branch='inbound NTLM authentication followed by a privileged target-side effect'; missing='The current rule detects source inconsistency but never requires a target effect and therefore conflates relay with proxies'; signal='NTLM authentication causally joined to a privileged change on the same target and account'; event='/(4624|4776)/'; extra='$e.security_result.authentication.type = "NTLM"'; type='rewrite'},
  @{n='impacket_packet_capture_or_raw_socket'; p='IMP-19'; c='packet'; branch='packet-capture driver, raw socket, or capture API activation'; missing='Kernel driver load, capture-filter creation, and process attribution are not separate branches'; signal='Unexpected capture driver load by an unapproved process'; event='/(6|DRIVER_LOAD|NETWORK_CAPTURE_STARTED)/'; extra='$e.target.file.full_path = /(?i)(npcap|npf|packet)/'; type='compensating_rule'},
  @{n='impacket_privilege_path_effects'; p='IMP-22'; c='kerberos'; branch='directory privilege-path mutation followed by anomalous ticket issuance or use'; missing='No proof that the changed object participates in the later ticket identity or authorization path'; signal='Sensitive directory mutation joined by object SID to later privileged ticket use'; event='/(5136|5137|4741|4742)/'; extra='$e.target.resource.attribute.labels["privilege_path_change"] = "true"'; type='rewrite'},
  @{n='impacket_rapid_scheduled_task_create_and_run'; p='IMP-04'; c='task'; branch='task registration followed by execution'; missing='Task updates, remote registration identity, XML action risk, and execution without a collected run event'; signal='4698/106 task creation with risky action and remote logon attribution'; event='/(4698|106)/'; extra='$e.target.resource.attribute.labels["task_action_risk"] = "high"'; type='compensating_rule'},
  @{n='impacket_remote_account_or_group_change'; p='IMP-07'; c='account'; branch='remote account, computer, or group membership mutation'; missing='The rule does not distinguish privileged groups, created-then-deleted accounts, or bind the change to a remote logon'; signal='Privileged membership change with actor/source attribution'; event='/(4728|4732|4756)/'; extra='$e.target.group.attribute.labels["privileged"] = "true"'; type='patch'},
  @{n='impacket_remote_registry_activity'; p='IMP-14'; c='registry'; branch='RemoteRegistry activation or sensitive value mutation'; missing='Service activation and registry mutation are broad alternatives with no remote caller or sensitive-key requirement'; signal='RemoteRegistry start followed by remote sensitive-key write'; event='/(4657|12|13|14)/'; extra='$e.target.registry.registry_key = /(?i)(SAM|SECURITY|SYSTEM|Terminal Server|Run)/'; type='rewrite'},
  @{n='impacket_remote_rpc_discovery'; p='IMP-08,IMP-16'; c='rpc'; branch='remote RPC endpoint/interface discovery'; missing='A fixed count ignores rare sensitive interfaces, distributed discovery, and per-host baselines'; signal='First-seen source invoking a sensitive RPC interface UUID'; event='RPC_CALL'; extra='$e.target.resource.attribute.labels["sensitive_rpc_interface"] = "true"'; type='compensating_rule'},
  @{n='impacket_remote_service_binary_sequence'; p='IMP-03'; c='service'; branch='administrative-share binary write followed by service installation'; missing='Filename/path identity is not joined and service start or resulting child process is absent'; signal='5145 write joined by normalized path/hash to 7045/4697 service image'; event='5145'; extra='$e.target.file.sha256 = $hash'; type='rewrite'},
  @{n='impacket_remote_wmi_activity'; p='IMP-05'; c='wmi'; branch='remote WMI method execution and provider-spawned process'; missing='Provider child detection misses processless methods, remote caller attribution, and failed attempts'; signal='WMI-Activity method invocation from a remote source followed by provider child'; event='/(5857|5858|5860|5861)/'; extra='$e.principal.ip = $source'; type='compensating_rule'},
  @{n='impacket_sensitive_file_or_replication_access'; p='IMP-13'; c='smb'; branch='directory replication rights use or credential-store file access'; missing='Replication and file access are materially different signals and should not share one broad predicate'; signal='4662 replication extended right by a non-DC principal'; event='4662'; extra='$e.target.resource.attribute.labels["replication_extended_right"] = "true"'; type='split'},
  @{n='impacket_sensitive_ldap_search'; p='IMP-09'; c='rpc'; branch='LDAP search for credential, delegation, or authorization attributes'; missing='Single sensitive filters, result volume, paged searches, and identity baselines are not separately assessed'; signal='1644 sensitive-attribute query by an unusual caller'; event='1644'; extra='$e.target.resource.attribute.labels["sensitive_ldap_filter"] = "true"'; type='patch'},
  @{n='impacket_short_lived_command_service'; p='IMP-03'; c='service'; branch='command-bearing service creation and short lifetime'; missing='The rule name claims short-lived behavior but has no deletion/stop event and overweights shell strings'; signal='Service create followed by start and delete under one service identity'; event='/(7045|4697)/'; extra='$e.target.resource.name = $service'; type='rewrite'},
  @{n='impacket_smb_sensitive_file_activity'; p='IMP-01,IMP-13'; c='smb'; branch='remote SMB access to credential-bearing or administrative paths'; missing='Share authorization checks, read/write direction, object sensitivity, and source baseline are conflated'; signal='Successful read of credential-store file by a non-management source'; event='5145'; extra='$e.security_result.action = "ALLOW"'; type='patch'},
  @{n='impacket_suspicious_kerberos_requests'; p='IMP-11'; c='kerberos'; branch='uncommon or high-volume AS/TGS request behavior'; missing='A count-only threshold misses targeted single requests and does not inspect encryption, options, preauthentication, SPN or outcome'; signal='Risky ticket properties or rare requester-to-service relationship'; event='/(4768|4769|4771)/'; extra='$e.target.resource.attribute.labels["kerberos_request_risk"] = "high"'; type='rewrite'},
  @{n='impacket_suspicious_service_control'; p='IMP-03'; c='service'; branch='remote logon followed by service creation or configuration'; missing='The events are joined only by host and may associate unrelated administrators; service change/start/delete paths are absent'; signal='Remote logon session joined by logon ID to service mutation'; event='4624'; extra='$e.extensions.auth.mechanism = /NTLM|KERBEROS/'; type='rewrite'},
  @{n='impacket_terminal_services_control'; p='IMP-18'; c='registry'; branch='Terminal Services session connect, disconnect, reconnect, or logoff control'; missing='Common session lifecycle events lack caller-to-target-session attribution and administrative control semantics'; signal='Session-control event where actor differs from target session user'; event='/(4778|4779|23|24|25)/'; extra='$e.principal.user.userid != $e.target.user.userid'; type='patch'},
  @{n='impacket_unusual_protocol_listener'; p='IMP-02'; c='smb'; branch='new listener on SMB or relay-associated ports'; missing='Port-only detection lacks process trust, host role, first-seen status, and bind-address context'; signal='First-seen unapproved process listening on a restricted service port'; event='NETWORK_LISTEN'; extra='$e.target.port = /(445|139|80|443)/'; type='patch'},
  @{n='impacket_unusual_service_authentication'; p='IMP-15'; c='account'; branch='failed or unusual authentication to SQL, MQTT, RDP, or SMB'; missing='Ten failures is generic and misses successful first-seen protocol/account pairs and distributed attempts'; signal='Successful authentication on a first-seen account-service-host relationship'; event='AUTHENTICATION'; extra='$e.security_result.action = "ALLOW"'; type='compensating_rule'},
  @{n='impacket_wmi_subscription_change'; p='IMP-06'; c='wmi'; branch='WMI filter, consumer, and binding creation'; missing='Single events do not prove a complete subscription and permanent repository changes may lack Sysmon'; signal='Filter-consumer-binding triad joined by subscription identity'; event='/(19|20|21|5861)/'; extra='$e.target.resource.name = $subscription'; type='rewrite'}
)
$out = Join-Path $root 'public-rules/comparisons/impacket'
New-Item -ItemType Directory -Force -Path $out | Out-Null
foreach ($d in $data) {
  $internalRel = "detections/impacket/yaral/$($d.n).yaral"
  $internal = Join-Path $root $internalRel
  $pubRel = $candidates[$d.c]
  $pub = Join-Path $root $pubRel
  if (!(Test-Path $pub)) { throw "Missing candidate $pubRel" }
  $ih = (Get-FileHash $internal -Algorithm SHA256).Hash.ToLowerInvariant()
  $ph = (Get-FileHash $pub -Algorithm SHA256).Hash.ToLowerInvariant()
  $pubLink = '../../' + ($pubRel -replace '\\','/')
  $proposal = "$($d.n)_strong_branch"
  $eventExpression = if ($d.event -match '^/.+/$') { $d.event } else { '"' + $d.event + '"' }
  if ($d.type -eq 'rewrite') {
    $rewriteExtra = $d.extra -replace '\$e\.', '$a.'
    $proposalBody = @"
  events:
    `$a.metadata.product_event_type = $eventExpression
    `$a.principal.hostname = `$host
    $rewriteExtra
    `$a.principal.user.userid = `$actor
    `$b.principal.hostname = `$host
    `$b.principal.user.userid = `$actor
    `$b.metadata.event_type = "STATUS_UPDATE"
    `$b.target.resource.attribute.labels["sensitive_effect"] = "true"
    `$a.metadata.event_timestamp.seconds <= `$b.metadata.event_timestamp.seconds
  match:
    `$host, `$actor over 15m
  condition:
    `$a and `$b
"@
  } else {
    $proposalBody = @"
  events:
    `$e.metadata.product_event_type = $eventExpression
    `$e.principal.hostname = `$host
    $($d.extra)
  match:
    `$host over 15m
  condition:
    `$e
"@
  }
  $text = @"
# Public-rule comparison: $($d.n)

## Identity and independence gate

- Internal tool: ``impacket``
- Internal canonical rule: ``$internalRel``
- Internal SHA-256: ``$ih``
- Internal review completed before public comparison: ``yes``
- Procedure IDs: ``$($d.p)``
- Scope mapping rationale: candidates were mapped by procedure, observable effect and telemetry rather than name or syntax.

Public candidate:
- [``$pubRel``]($pubLink) - SHA-256 ``$ph``

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite or remote access context | Partial; depends on fields present in the canonical events | Candidate provides adjacent behavior but not an Impacket-specific prerequisite | Network logon or authenticated remote caller - moderate | First-seen source/account/host relationship | complementary | Internal ``$($d.p)`` inventory and cited public rule. |
| $($d.branch) | Canonical rule covers the principal event family | Candidate covers an overlapping effect with different assumptions | $($d.signal) - strong | Process, network-session, and resulting-object correlation - moderate | complementary | The security-sensitive effect is closer to intent than executable names. |
| Resulting effect and cleanup | Incomplete | Incomplete or outside candidate scope | Verified resulting state - strong | stop/delete, object access, or later authentication - moderate | different_scope | Neither rule demonstrates every downstream effect. |

## Missing detection branches

- Missing from ours: $($d.missing).
- Missing from public: complete Impacket procedure ordering, target-side effect confirmation, and coverage independent of mutable tool names.
- Missing from both: reliable observation when collection is partial, identity normalization fails, or the procedure is split across sources and time windows.

## Detection edge cases and blind spots

The logic must account for NAT and management relays, machine-versus-user identity forms, delayed ingestion, duplicate events, clock skew, host-role differences, and partial endpoint/DC collection. A fixed correlation window can miss low-and-slow activity, while broad host-only joins can connect unrelated administrative work. Legitimate remote administration can produce the same primitives, so approved-source enrichment should inform severity rather than suppress the security effect outright.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| $($d.signal) | strong | proposed/internal refinement | Close to the sensitive operation and resistant to binary renaming. | Requires the declared provider fields and semantic enrichment. |
| Remote caller or network-logon context | moderate | ours/compensating | Adds causal attribution but is not independently malicious. | Proxies, jump hosts and logon-ID normalization complicate joins. |
| Tool, image, service, task, or object name | weak | some public branches | Useful investigative context, not durable behavior. | Mutable and may collide with benign administration. |

## Public-rule weaknesses

The candidate is valuable corroboration but covers only an adjacent branch, inherits its backend's field and collection assumptions, and cannot establish the complete Impacket procedure. Name/path indicators and fixed exclusions are weak when not paired with a security effect. Its thresholds are not tenant evidence and must not be copied blindly.

## Internal-rule weaknesses

$($d.missing). The canonical rule also needs explicit collection-health assumptions and stronger entity joins. It can over-alert on legitimate administration when the sensitive effect is broad, and under-alert when events are distributed or delayed.

## Decision trail

- Candidate improvement: independently add the strong branch below, retaining the existing rule until sanitized telemetry proves whether a split or replacement is appropriate.
- Independent verification: required against pinned Impacket source analysis, provider documentation, local schema mappings, and authorized fixtures.
- Decision: ``deferred_pending_rule_improvement_run``
- Reason: public logic is comparative evidence, not authority; this proposal has not passed internal adversarial review.
- Required regeneration: canonical review, coverage, telemetry and master counts, all five translations, dependencies/manifests/hashes, then this comparison.

## Unmatched scope

The public candidate does not cover all of ``$($d.p)``. Unrelated public rules were not treated as equivalents, and no global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: ``$($d.type)``
- Addresses branches: $($d.missing).
- Required telemetry: normalized event type, actor/account, source, destination, result, stable object/session identifiers, and the enrichment referenced in the predicate.
- Validation status: ``unvalidated_proposal``

``````yaral
rule $proposal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "$($d.p)"
    source_comparison = "unvalidated_proposal"
$proposalBody
}
``````

This proposal strengthens a procedure-level branch without importing the public predicate. It remains vulnerable to missing source telemetry, semantic mapping errors, and activity outside the correlation period. If adopted, test benign administrative workloads and missing-data behavior, then update every downstream artifact required by the workflow.
"@
  Set-Content -Path (Join-Path $out "$($d.n).md") -Value $text -Encoding utf8
}
$rows = $data | ForEach-Object { "| [``$($_.n)``](./$($_.n).md) | ``$($_.p)`` | $($_.type) | deferred_pending_rule_improvement_run |" }
$index = @"
# Impacket public-rule comparison index

All 20 canonical Impacket YARA-L rules have procedure-branch comparisons. Public rules are untrusted comparative evidence. Every proposed code block is an ``unvalidated_proposal`` and no canonical rule was changed by this comparison pass.

| Internal rule | Procedures | Proposal | Decision |
| --- | --- | --- | --- |
$($rows -join "`n")

## Portfolio findings

- Strong internal branches include target-side service, task, WMI, directory, replication and SMB effects.
- Recurring weaknesses are host-only joins, count-only conditions, missing stable session/object identity, conflated signals, and absent result/cleanup confirmation.
- Public rules add useful adjacent signals and telemetry-specific branches but frequently have narrower procedure scope or mutable-name assumptions.
- Adoption requires source and telemetry verification plus the full canonical review and downstream regeneration workflow.
"@
Set-Content -Path (Join-Path $out 'INDEX.md') -Value $index -Encoding utf8
