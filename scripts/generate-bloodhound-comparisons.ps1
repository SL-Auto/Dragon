$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root 'public-rules/comparisons/bloodhound'
New-Item -ItemType Directory -Force -Path $out | Out-Null

$elasticRev='7e91c156324cdc64cda27f7fec7067b1148074ef'
$chronRev='234e9223c3b8f3d1c30209d9663797ba69057533'
$candidates = @{
  azure = @{ Path="public-rules/snapshots/elastic-security/$elasticRev/rules/integrations/azure/discovery_bloodhound_user_agents_detected.toml"; Hash='ae4b54c0bd1908c0eefc9f7b8e315a543ee1e3e5795578329fea972e02ffac60'; Note='Elastic AzureHound user-agent rule' }
  ad = @{ Path="public-rules/snapshots/elastic-security/$elasticRev/rules/windows/discovery_high_number_ad_properties.toml"; Hash='260d763e6cc776634fb023e536f32c6fdd6b4cb8ce889726aa0b16cb2c41aa95'; Note='Elastic high-volume AD property access rule' }
  graph = @{ Path="public-rules/snapshots/chronicle-community/$chronRev/rules-community/microsoft/graph_activity/ms_graph_user_and_group_enumeration.yaral"; Hash='9429e64930b0f25065a9da552f6656948cf350dc7a9c8fc1aac7a66c93e093b3'; Note='Chronicle Graph user/group enumeration rule' }
  sysvol = @{ Path="public-rules/snapshots/chronicle-community/$chronRev/rules-community/microsoft/windows/copy_from_or_to_admin_share_or_sysvol_folder.yaral"; Hash='946ddcae11a6b37746335cc252b049205afa129f38dcf1b3d39c56945caadeec'; Note='Chronicle administrative-share/SYSVOL transfer rule' }
  archive = @{ Path="public-rules/snapshots/elastic-security/$elasticRev/rules_building_block/collection_posh_compression.toml"; Hash='e1393ea2bfc404db1a32e2ca4b1deda3d907371d53f9477ac168d98942ddd5ed'; Note='Elastic PowerShell compression building block' }
}

$rules = @(
@{n='bloodhound_collector_process_network_context'; p='BH-001'; c='ad'; branch='collector process starts and establishes directory or cloud-management connections'; ours='rare process plus five process-attributed LDAP/Graph/ARM connections'; pub='high-volume AD property access, without process/network sequence'; missing='signed-but-new collectors; common host processes loading collector code; single-protocol or slow activity'; edge='Process paths are mutable, prevalence can lag, NAT can blur cloud sources, and process/network joins may break across sensors.'; strong='process-attributed sensitive-service connection followed by confirmed enumeration'; weak='rare executable path alone'; verdict='complementary'; type='compensating_rule'; prop='bloodhound_process_to_directory_effect'; event='$p.metadata.event_type = "PROCESS_LAUNCH"`n    $p.principal.hostname = $host`n    $p.target.process.product_specific_process_id = $pid`n    $q.metadata.product_event_type = /(LDAP_SEARCH|MicrosoftGraphActivityLogs|AZURE_RESOURCE_READ)/`n    $q.principal.hostname = $host`n    $q.principal.process.product_specific_process_id = $pid`n    $q.target.resource.name = $object'; match='$host, $pid over 20m'; outcome='$objects = count_distinct($object)'; cond='$p and $objects >= 25'; req='stable process entity on process launch and LDAP/Graph/ARM read events'}
@{n='bloodhound_ldap_directory_discovery_fanout'; p='BH-002,BH-004'; c='ad'; branch='one identity enumerates multiple AD object categories and topology relationships'; ours='five normalized object categories in 15 minutes'; pub='many distinct AD properties accessed by one process'; missing='single-category deep pagination, multi-DC distribution, slow collection, and category-normalization failure'; edge='1644 is selective and expensive; identity forms and source attribution differ by DC; legitimate identity governance has similar breadth.'; strong='process-attributed multi-category LDAP searches with sensitive topology attributes'; weak='raw query count without category or caller context'; verdict='complementary'; type='compensating_rule'; prop='bloodhound_ldap_deep_single_category_enumeration'; event='$e.metadata.product_event_type = /(LDAP_SEARCH|1644)/`n    $e.principal.user.userid = $user`n    $e.principal.hostname = $host`n    $e.target.resource.attribute.labels["naming_context"] = $nc`n    $e.target.resource.attribute.labels["result_object_id"] = $object'; match='$host, $user, $nc over 30m'; outcome='$objects = count_distinct($object)'; cond='$e and $objects >= 500'; req='LDAP search result cardinality or result-object identifiers, caller identity and naming context'}
@{n='bloodhound_sensitive_directory_attribute_reads'; p='BH-003,BH-005'; c='ad'; branch='LDAP reads request security descriptors or AD CS relationship attributes'; ours='single requested-attribute match'; pub='unusually high number of AD properties'; missing='control-only security-descriptor reads, attribute aliases, and low-volume targeted reads'; edge='4662 usually records access rather than the full LDAP projection; requested-attribute fields require uncommon directory or EDR instrumentation.'; strong='caller-attributed LDAP control/attribute request for security descriptors or certificate topology'; weak='a lone 4662 without operation/property resolution'; verdict='ours_stronger'; type='rewrite'; prop='bloodhound_sensitive_directory_relationship_reads'; event='$e.metadata.product_event_type = /(LDAP_SEARCH|1644)/`n    $e.principal.user.userid = $user`n    ($e.target.resource.attribute.labels["sd_flags_control"] = "true" or re.regex($e.target.resource.attribute.labels["requested_attributes"], `(?i)(nTSecurityDescriptor|msPKI-|pKIEnrollmentService|certificateTemplates)`))`n    $e.target.resource.name = $object'; match='$user over 20m'; outcome='$objects = count_distinct($object)'; cond='$e and $objects >= 10'; req='LDAP requested attributes and controls, resolved target object, and caller identity'}
@{n='bloodhound_smb_rpc_host_sweep'; p='BH-006'; c='ad'; branch='one process resolves and probes many hosts over SMB/RPC'; ours='20 distinct 135/139/445 destinations in ten minutes'; pub='no material host-sweep equivalent; closest rule observes downstream AD property access'; missing='DNS-only discovery, failed probes missing from flow, IPv6, slow/distributed sweeps, and target-host rather than IP counting'; edge='Shared scanners and management systems dominate false positives; IP churn can inflate cardinality while NAT can merge actors.'; strong='process-attributed east-west multi-host connection fanout with failure/success context'; weak='port fanout without internal-scope or process trust context'; verdict='ours_stronger'; type='patch'; prop='bloodhound_smb_rpc_host_sweep_internal_untrusted'; event='$e.metadata.event_type = "NETWORK_CONNECTION"`n    $e.principal.hostname = $host`n    $e.principal.process.product_specific_process_id = $pid`n    $e.target.ip = $target`n    $e.target.port = /(135|139|445)/`n    $e.target.ip_in_internal_range = true`n    $e.principal.process.file.labels["approved_scanner"] = "false"'; match='$host, $pid over 30m'; outcome='$targets = count_distinct($target)'; cond='$e and $targets >= 15'; req='process-attributed attempted connections, internal-address enrichment, stable process entity and governed scanner inventory'}
@{n='bloodhound_remote_session_registry_collection'; p='BH-007,BH-008'; c='ad'; branch='SRVSVC session enumeration or remote logged-on-user registry reads across hosts'; ours='operation-name regex and five targets'; pub='no equivalent procedure branch'; missing='endpoint-local RPC telemetry, operation UUID/opnum forms, single high-value target and mixed SRVSVC/registry sequences'; edge='Operation labels are vendor-normalized and may omit encrypted RPC detail; helpdesk and inventory agents can be broad.'; strong='resolved NetSessionEnum or remote-registry logged-on-user operation with source process'; weak='generic RPC_CALL label'; verdict='ours_stronger'; type='rewrite'; prop='bloodhound_remote_session_or_loggedon_collection'; event='$e.metadata.product_event_type = /(RPC_CALL|REGISTRY_READ)/`n    $e.principal.hostname = $source`n    $e.principal.process.product_specific_process_id = $pid`n    $e.target.hostname = $target`n    ($e.target.resource.attribute.labels["rpc_operation_id"] = "SRVSVC:NetSessionEnum" or re.regex($e.target.registry.registry_key, `(?i)HKEY_USERS|Volatile Environment`))'; match='$source, $pid over 30m'; outcome='$targets = count_distinct($target)'; cond='$e and $targets >= 3'; req='resolved RPC interface/operation or full remote registry path, source process and target host'}
@{n='bloodhound_samr_local_group_enumeration'; p='BH-009,BH-010'; c='ad'; branch='SAMR alias membership and LSA account-right reads across hosts'; ours='combined SAMR/LSA regex and five targets'; pub='no equivalent RPC procedure coverage'; missing='different telemetry schemas for SAMR and LSA, single sensitive host, opnum-only sensors and local rights reads'; edge='Combining interfaces hides different benign baselines and parser mappings; encrypted RPC may expose only interface UUID.'; strong='resolved SAMR alias-member or LSA account-right operation with caller process'; weak='interface-only RPC connection'; verdict='ours_stronger'; type='split'; prop='bloodhound_samr_alias_membership_fanout'; event='$e.metadata.product_event_type = "RPC_CALL"`n    $e.principal.hostname = $source`n    $e.target.hostname = $target`n    $e.target.resource.attribute.labels["rpc_interface"] = /(?i)SAMR/`n    $e.target.resource.attribute.labels["rpc_operation"] = /(?i)(GetMembersInAlias|EnumerateAliases)/'; match='$source over 30m'; outcome='$targets = count_distinct($target)'; cond='$e and $targets >= 3'; req='RPC interface plus resolved operation, source identity/process and target host; a separate LSA rule remains required'}
@{n='bloodhound_sysvol_policy_file_collection'; p='BH-011'; c='sysvol'; branch='one source reads multiple attack-path-relevant Group Policy artifacts from SYSVOL'; ours='three distinct named policy paths'; pub='copy to or from administrative shares/SYSVOL using process and share context'; missing='FILE_READ paths using UNC normalization variants, single sensitive file, DFS referral paths, and slow reads'; edge='Normal Group Policy refresh is extremely common and service accounts may legitimately inventory all policies.'; strong='non-GPSVC process reading multiple sensitive policy types across GPOs'; weak='any SYSVOL share access'; verdict='ours_stronger'; type='patch'; prop='bloodhound_sysvol_policy_file_collection_process_attributed'; event='$e.metadata.product_event_type = /(5145|FILE_READ)/`n    $e.principal.hostname = $source`n    $e.principal.process.file.full_path = $process`n    $e.principal.process.file.labels["is_group_policy_service"] = "false"`n    re.regex($e.target.file.full_path, `(?i)\\\\SYSVOL\\.*\\Policies\\.*(Groups.xml|GptTmpl.inf|Registry.pol)$`)`n    $e.target.file.full_path = $path'; match='$source, $process over 30m'; outcome='$paths = count_distinct($path)'; cond='$e and $paths >= 3'; req='5145 or EDR file reads with normalized UNC path and process/service attribution'}
@{n='bloodhound_remote_security_configuration_reads'; p='BH-012'; c='ad'; branch='remote reads collect CA, Netlogon, LDAP, NTLM or NTDS security settings'; ours='broad registry path regex across two hosts'; pub='no material remote configuration-read equivalent'; missing='local reads after remote execution, named-value specificity, one DC/CA target, and WMI/API alternatives'; edge='4656/4663 requires object auditing and often lacks remote source; broad LDAP/Lsa terms can match unrelated keys.'; strong='remote caller attributed read of a precise security-relevant registry value'; weak='generic registry read containing LDAP'; verdict='ours_stronger'; type='rewrite'; prop='bloodhound_remote_security_configuration_value_reads'; event='$e.metadata.product_event_type = /(REGISTRY_READ|4656|4663)/`n    $e.principal.hostname = $source`n    $e.target.hostname = $target`n    re.regex($e.target.registry.registry_key, `(?i)(CertSvc\\Configuration|Netlogon\\Parameters|Lsa\\MSV1_0|NTDS\\Parameters)`)`n    re.regex($e.target.registry.registry_value_name, `(?i)(StrongCertificateBindingEnforcement|CertificateMappingMethods|RestrictNTLM|LDAPServerIntegrity|LdapEnforceChannelBinding)`)' ; match='$source over 30m'; outcome='$values = count_distinct($e.target.registry.registry_value_name)'; cond='$e and $values >= 2'; req='full registry key and value name, source and target host, remote/local access attribution'}
@{n='bloodhound_service_protocol_probe_fanout'; p='BH-013'; c='ad'; branch='one process probes WebDAV, SMB, LDAP and LDAPS capability across many hosts'; ours='15 targets on any listed port, without protocol diversity'; pub='no equivalent multi-protocol collection branch'; missing='protocol-family diversity, connection results, HTTP WebDAV methods, low-and-slow probes and DNS'; edge='The current rule can fire on ordinary web browsing or SMB-only scanners because it does not require multiple service families.'; strong='same process probes several relevant protocols across many internal targets'; weak='target count on a union of common ports'; verdict='different_scope'; type='rewrite'; prop='bloodhound_multi_protocol_capability_probe'; event='$e.metadata.event_type = "NETWORK_CONNECTION"`n    $e.principal.hostname = $host`n    $e.principal.process.product_specific_process_id = $pid`n    $e.target.ip = $target`n    $e.target.resource.attribute.labels["service_family"] = $service`n    $service = /(?i)(webdav|smb|ldap|ldaps)/'; match='$host, $pid over 30m'; outcome='$targets = count_distinct($target)`n    $services = count_distinct($service)'; cond='$e and $targets >= 10 and $services >= 3'; req='process-attributed flows with reliable application/service classification and internal target identity'}
@{n='bloodhound_recurrent_collection_activity'; p='BH-014'; c='ad'; branch='the same collector entity repeats directory or host-enumeration bursts'; ours='100 events and five targets within one four-hour bucket'; pub='point-in-time AD property threshold only'; missing='separate burst detection, recurrence across process restarts, host/user correlation, jitter spanning windows and cloud activity'; edge='A flat event count does not prove recurrence and PID reuse can correlate unrelated activity.'; strong='two or more independently suspicious collection bursts tied to stable signer/user/host identity'; weak='large four-hour raw event count'; verdict='public_stronger'; type='rewrite'; prop='bloodhound_recurrent_collection_bursts'; event='$e.metadata.product_event_type = "DETECTION"`n    $e.about.labels["detection_family"] = /(?i)bloodhound_collection_burst/`n    $e.principal.hostname = $host`n    $e.principal.user.userid = $user`n    $e.metadata.id = $burst'; match='$host, $user over 24h'; outcome='$bursts = count_distinct($burst)'; cond='$e and $bursts >= 2'; req='upstream normalized collection-burst detections with stable host/user identity and unique burst ID'}
@{n='bloodhound_collection_archive_creation'; p='BH-015'; c='archive'; branch='multiple JSON collection files are created then packaged into an archive'; ours='same PID creates three JSON files and ZIP/7z in ten minutes'; pub='PowerShell compression command/activity building block'; missing='CSV output, process restart, non-ZIP output, in-memory output, service output and deletion lifecycle'; edge='PID reuse and missing process entity IDs can misjoin; JSON archiving is common; the public PowerShell branch is implementation-specific.'; strong='same stable process entity creates several collector-schema files and an archive'; weak='archive extension or compression command alone'; verdict='complementary'; type='rewrite'; prop='bloodhound_collection_artifact_packaging'; event='$j.metadata.product_event_type = /(11|FILE_CREATION)/`n    $j.principal.process.product_specific_process_id = $entity`n    re.regex($j.target.file.full_path, `(?i)\.(json|csv)$`)`n    $j.target.file.md5 = $schema`n    $a.metadata.product_event_type = /(11|FILE_CREATION)/`n    $a.principal.process.product_specific_process_id = $entity`n    re.regex($a.target.file.full_path, `(?i)\.(zip|7z)$`)'; match='$entity over 20m'; outcome='$schemas = count_distinct($schema)'; cond='$schemas >= 3 and $a'; req='stable process entity, file creates, extensions, and privacy-safe collector-schema fingerprint enrichment'}
@{n='bloodhound_azure_authentication_context'; p='BH-016'; c='azure'; branch='a cloud sign-in is followed by broad Graph or ARM reads from the same principal/source'; ours='sign-in plus twenty reads in thirty minutes'; pub='AzureHound user-agent activity without requiring sign-in correlation'; missing='managed identity/no sign-in, token refresh, source-IP changes, app identity joins and low-volume targeted reads'; edge='Cloud audit delays can invert ordering; service-principal sign-ins may not share source IP with downstream gateways.'; strong='app/principal-correlated authentication followed by broad read families'; weak='user agent alone'; verdict='complementary'; type='rewrite'; prop='bloodhound_azure_authentication_to_enumeration'; event='$s.metadata.product_event_type = /(SigninLogs|AADServicePrincipalSignInLogs)/`n    $s.principal.user.userid = $principal`n    $s.principal.application = $app`n    $r.metadata.product_event_type = /(MicrosoftGraphActivityLogs|AZURE_RESOURCE_READ)/`n    $r.principal.user.userid = $principal`n    $r.principal.application = $app`n    $r.target.resource.attribute.labels["resource_family"] = $family'; match='$principal, $app over 60m'; outcome='$families = count_distinct($family)'; cond='$s and $families >= 5'; req='sign-in and Graph/ARM audit with normalized principal object ID and application/service-principal ID'}
@{n='bloodhound_azure_graph_enumeration_fanout'; p='BH-017'; c='graph'; branch='one principal reads many Graph directory resource families'; ours='six normalized families in thirty minutes'; pub='specific user/group enumeration requests and known Graph reconnaissance patterns'; missing='single-family deep enumeration, pagination volume, application/relationship endpoints, multi-IP service principals and batch requests'; edge='Resource-family enrichment may collapse or omit paths; governance and sync applications have very broad legitimate access.'; strong='rare app/principal enumerates multiple relationship-bearing Graph families or extreme object count'; weak='one GET to users or groups'; verdict='complementary'; type='compensating_rule'; prop='bloodhound_graph_deep_relationship_enumeration'; event='$e.metadata.product_event_type = "MicrosoftGraphActivityLogs"`n    $e.principal.user.userid = $principal`n    $e.principal.application = $app`n    $e.network.http.method = "GET"`n    re.regex($e.target.url, `(?i)/(users|groups|servicePrincipals|applications)/.*(memberOf|owners|appRoleAssignments|transitiveMembers)`)`n    $e.target.resource.name = $object'; match='$principal, $app over 30m'; outcome='$objects = count_distinct($object)'; cond='$e and $objects >= 100'; req='Graph audit with normalized URL, app/principal IDs and returned or targeted object identity'}
@{n='bloodhound_azure_resource_enumeration_fanout'; p='BH-018'; c='azure'; branch='one principal reads many ARM provider and scope families'; ours='six provider families tied to principal and source IP'; pub='AzureHound user-agent detection identifies implementation but not breadth'; missing='resource-list pagination in one provider, multi-IP automation, subscription fanout and management-group traversal'; edge='AzureActivity does not consistently contain read-plane operations; gateway coverage and provider normalization vary.'; strong='principal/app reads multiple provider families across subscriptions or management groups'; weak='AzureHound user agent or six providers without rarity/baseline'; verdict='complementary'; type='rewrite'; prop='bloodhound_arm_scope_and_provider_fanout'; event='$e.metadata.product_event_type = /(?i)(AZURE_RESOURCE_READ|AzureActivity)/`n    $e.principal.user.userid = $principal`n    $e.principal.application = $app`n    $e.target.resource.attribute.labels["provider_family"] = $provider`n    $e.target.resource.attribute.labels["subscription_id"] = $subscription'; match='$principal, $app over 60m'; outcome='$providers = count_distinct($provider)`n    $subscriptions = count_distinct($subscription)'; cond='$e and $providers >= 5 and $subscriptions >= 2'; req='ARM read-plane audit with app/principal, provider family and subscription/management scope'}
@{n='bloodhound_azure_rbac_enumeration'; p='BH-019'; c='azure'; branch='principal reads RBAC assignments, definitions, ownership, policy or eligibility across scopes'; ours='operation regex and ten distinct scopes'; pub='AzureHound user-agent rule gives implementation attribution but does not isolate RBAC'; missing='single high-value scope, Graph role-management endpoints, pagination, inherited assignments and multi-subscription distribution'; edge='Generic owners matching may include unrelated APIs; approved access-review platforms legitimately have high cardinality.'; strong='rare principal/app reads multiple authorization relationship types across sensitive scopes'; weak='ten scope names without resource sensitivity or result context'; verdict='ours_stronger'; type='rewrite'; prop='bloodhound_azure_authorization_relationship_enumeration'; event='$e.metadata.product_event_type = /(MicrosoftGraphActivityLogs|AZURE_RESOURCE_READ)/`n    $e.principal.user.userid = $principal`n    $e.principal.application = $app`n    $e.target.resource.attribute.labels["authorization_relationship"] = $relationship`n    $relationship = /(?i)(role_assignment|role_definition|owner|access_policy|eligibility)/`n    $e.target.resource.attribute.labels["scope_id"] = $scope'; match='$principal, $app over 60m'; outcome='$relationships = count_distinct($relationship)`n    $scopes = count_distinct($scope)'; cond='$e and $relationships >= 3 and $scopes >= 5'; req='Graph/ARM read audit enriched to authorization relationship type, stable app/principal and scope IDs'}
@{n='bloodhound_cloud_collection_output'; p='BH-020'; c='azure'; branch='sustained cloud reads correlate with local JSON output or collector service lifecycle'; ours='twenty reads plus any JSON create or 4697/7045 by same host/user'; pub='AzureHound user-agent signal, without endpoint output correlation'; missing='remote/cloud execution with no hostname, stdout/object-storage output, process entity join, service identity mismatch and non-JSON formats'; edge='Host/user is too coarse and can join unrelated inventory activity to any service installation or JSON file.'; strong='same process entity performs cloud reads and creates collector output'; weak='host/user correlation to generic JSON or service event'; verdict='public_stronger'; type='rewrite'; prop='bloodhound_cloud_read_to_local_output'; event='$n.metadata.product_event_type = /(MicrosoftGraphActivityLogs|AZURE_RESOURCE_READ)/`n    $n.principal.hostname = $host`n    $n.principal.process.product_specific_process_id = $entity`n    $n.target.resource.attribute.labels["resource_family"] = $family`n    $f.metadata.product_event_type = /(11|FILE_CREATION)/`n    $f.principal.hostname = $host`n    $f.principal.process.product_specific_process_id = $entity`n    re.regex($f.target.file.full_path, `(?i)\.(json|zip)$`)'; match='$host, $entity over 60m'; outcome='$families = count_distinct($family)'; cond='$families >= 5 and $f'; req='process-attributed Graph/ARM egress or gateway-to-process correlation plus endpoint file creation'}
)

foreach($r in $rules) {
  $internal="detections/bloodhound/yaral/$($r.n).yaral"
  $ih=(Get-FileHash (Join-Path $root $internal) -Algorithm SHA256).Hash.ToLower()
  $c=$candidates[$r.c]
  $rel='../../'+($c.Path -replace '^public-rules/','' -replace '\\','/')
  $proposalEvents=$r.event -replace '`n',"`n"
  $proposalOutcome=$r.outcome -replace '`n',"`n"
  $doc=@"
# Public-rule comparison: $($r.n)

## Identity and independence gate

- Internal tool: ``bloodhound``
- Internal canonical rule: ``$internal``
- Internal SHA-256: ``$ih``
- Internal review completed before public comparison: ``yes``
- Procedure IDs: ``$($r.p)``
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate:
- [$($c.Note)]($rel) - pinned revision and SHA-256 ``$($c.Hash)``.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| $($r.branch) | $($r.ours) | $($r.pub) | $($r.strong) - strong | $($r.weak) - weak | $($r.verdict) | Canonical rule, pinned public candidate, ``coverage/bloodhound.yml`` and ``reports/bloodhound/source-analysis.md``. |
| Activity is divided across identities, hosts, processes or windows | Usually falls below the current cardinality/join | Public candidate also lacks complete distributed correlation | stable entity plus procedure-specific effect - moderate | longer-window baseline/rare relationship - moderate | insufficient_evidence | This is an analytical inference requiring tenant telemetry validation. |

## Missing detection branches

- Missing from ours: $($r.missing).
- Missing from public rule: complete ordered procedure coverage and telemetry-independent attribution beyond its declared data source.
- Missing from both: reliable intent attribution and complete observation when required logging is absent.

## Detection edge cases and blind spots

$($r.edge) Low-and-slow and distributed activity can evade fixed per-entity windows. Partial collection can reduce cardinality without indicating benign behavior. Entity normalization must distinguish user, application, process and host identities.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| $($r.strong) | strong | ours/proposal | Close to the security-relevant collection effect and resistant to mutable filenames. | Requires the detailed telemetry declared below and authorized-tool baselining. |
| procedure-specific breadth or ordered correlation | moderate | ours | Adds behavioral context without asserting tool identity. | Thresholds and joins require local validation. |
| $($r.weak) | weak | public or current branch | Useful as a lead but not sufficient proof of collection. | Mutable or common in legitimate administration. |

## Public-rule weaknesses

The public candidate covers only its declared observable and does not establish the complete BloodHound collection procedure. Its implementation-specific or single-source signal can be absent while the same security effect remains observable elsewhere. It is valuable as independent compensating evidence, not authority.

## Internal-rule weaknesses

$($r.missing). The current threshold and entity join are detection hypotheses; collection loss can silently turn a strong sequence into no alert.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown below; no public predicate is copied.
- Independent verification: compare against pinned collector source, actual provider semantics, sanitized fixtures and benign inventory baselines.
- Decision: ``deferred_pending_rule_improvement_run``.
- Reason: comparison code is an unvalidated detection-engineering proposal, not canonical logic.
- Required regeneration: canonical review, coverage, telemetry, all translations, dependencies/hashes and this comparison after acceptance or modification.

## Unmatched scope

The pinned public candidate is not a complete equivalent. Branch-specific differences are retained as ``$($r.verdict)`` or ``insufficient_evidence`` rather than claiming either rule is globally better.

## Proposed YARA-L improvement

- Change type: ``$($r.type)``
- Addresses branches: $($r.missing).
- Required telemetry: $($r.req).
- Validation status: ``unvalidated_proposal``

``````yaral
rule $($r.prop) {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "$($r.p)"
  events:
    $proposalEvents
  match:
    $($r.match)
  outcome:
    $proposalOutcome
  condition:
    $($r.cond)
}
``````

Remaining gaps: intent is not established; thresholds, normalized fields and benign baselines require authorized telemetry testing. Distributed activity and missing collection require separate compensating analytics and collection-health monitoring.

If adopted, independently revise canonical YARA-L, re-run adversarial review, reconcile telemetry and master counts, regenerate all five translations and dependencies, and re-compare the final logic.
"@
  Set-Content -LiteralPath (Join-Path $out "$($r.n).md") -Value $doc -Encoding utf8
}

$rows=$rules|ForEach-Object{"| [$($_.n)](./$($_.n).md) | $($_.p) | $($_.verdict) | $($_.type) |"}
$index=@"
# BloodHound public-rule comparison index

Pinned public revisions: Elastic ``$elasticRev``; Chronicle ``$chronRev``.

All 16 canonical BloodHound rules were compared at procedure-branch level. Public coverage is sparse for RPC, remote registry and endpoint collector behavior, so closest candidates are explicitly treated as compensating or different-scope evidence. Proposed YARA-L remains ``unvalidated_proposal`` and no canonical rule was changed.

| Internal rule | Procedures | Headline conclusion | Proposed change |
| --- | --- | --- | --- |
$($rows -join "`n")

## Cross-rule findings

- Strong internal branches are process-attributed RPC/LDAP/network effects and ordered cloud-read-to-output correlations when the required fields exist.
- Weak branches rely on generic path regexes, host/user joins, raw cardinality, mutable process prevalence or broad common ports.
- Material gaps recur around stable entity joins, single-target deep collection, distributed and low-and-slow activity, cloud application identity, provider collection health and authoritative RPC/LDAP normalization.
- Public rules add useful AzureHound user-agent, AD-property volume, Graph endpoint and SYSVOL/compression signals, but none covers the whole collector procedure inventory.

## Review status

Threat-detection comparison complete for 16/16 BloodHound rules. Each document includes actual YARA-L 2.0 proposal code and required telemetry. Acceptance requires the separate canonical improvement workflow.
"@
Set-Content -LiteralPath (Join-Path $out 'INDEX.md') -Value $index -Encoding utf8
