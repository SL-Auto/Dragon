# bloodhound telemetry requirements

## Scope

- Tool revision: `bloodhound-v9.5.1_sharphound-a2f8435_common-fcb6cb9_azurehound-23735c8`
- Detection files: 21 one-rule-per-file canonical detections under `detections/bloodhound/yaral/`
- Generated/reviewed: 2026-08-15; five compensating rules added and reconciled 2026-11-21
- Status: `complete_for_experimental_rules`

## Consolidated collection plan

| Capability ID | Provider / product | Events / IDs | Required fields | Enablement / configuration | Retention / correlation | Known gaps | Supports |
| --- | --- | --- | --- | --- | --- | --- | --- |
| BH-TEL-01 | Windows Security, Sysmon and EDR | 4688, Sysmon 1, PROCESS_LAUNCH | host, user, process entity/path, parent, signer, prevalence | Enable process creation and command line; retain stable process IDs | 7 days; correlate process/network for 4 hours | in-process execution and weak prevalence mapping | BH-001,014,020 |
| BH-TEL-02 | AD DS diagnostic, directory audit and EDR/NDR | Directory Service 1644, LDAP_SEARCH, scoped 4662 | source process/account/IP, stable process entity, DC, naming context, base DN, scope, filter, requested attributes/controls, object category, result count, per-result object identity where the parser expands results | Enable LDAP query telemetry; use expensive/inefficient query logging only after capacity review; configure narrow SACLs where justified | 14 days; preserve source and event time | 4662 is not general query logging; LDAPS blocks passive inspection; 1644 and most EDR events summarise results rather than listing objects | BH-001–005 |
| BH-TEL-03 | DNS, EDR, firewall and NDR | NETWORK_DNS, NETWORK_CONNECTION, Security 5156 | source process/host, user, target IP/host/port, protocol, result | Enable process-attributed network and central DNS; collect east-west flows | 14 days; cardinality windows 10–30 minutes | perimeter sensors often lack process identity | BH-001,006,013,014 |
| BH-TEL-04 | EDR/NDR RPC telemetry | RPC_CALL for SRVSVC, SAMR, LSA policy and Remote Registry | source/target, account, process, interface name and UUID, operation name or opnum (SAMR 15/33), result | Enable east-west RPC metadata and endpoint attribution | 14 days; source-to-target joins 15–20 minutes | standard Windows logs usually omit read operation detail | BH-007–010,012,014 |
| BH-TEL-05 | Windows Security and SMB telemetry | 5140, 5145 | source IP/host, account/logon ID, share, relative path, access mask, target | Enable File Share and scoped Detailed File Share auditing on DC/SYSVOL and managed targets | 14 days; correlate to source process/RPC | 5140 lacks file path; 5145 can be high volume | BH-006–008,011,013 |
| BH-TEL-06 | EDR and scoped Windows Object Access | REGISTRY_READ, 4656, 4663 | source process/account, reading process path, target host, complete key path and value name, access mask/result | Enable verified registry-read mapping or narrow Read-value SACLs on Services\Kdc, Control\SecurityProviders\Schannel, Control\Lsa, Control\Lsa\MSV1_0 and CertSvc\Configuration; forward RemoteRegistry service events | 14 days | Sysmon records registry changes, not reads; 4656/4663 record key and access mask but not value name; remote initiator may be absent | BH-008,012 |
| BH-TEL-07 | Sysmon and EDR file lifecycle | Sysmon 11, 23, 26; FILE_CREATION, FILE_READ, FILE_DELETION | stable process entity, user, full path, extension, operation, hash | Enable file create/read/delete for collector output and SYSVOL paths | 7 days; correlate create/archive/delete within 10 minutes | file reads and rapid temporary files may be missing | BH-001,011,015,020 |
| BH-TEL-08 | Windows Security and Service Control Manager | 4697, System 7045, 7036 | actor, host, service, image path, account, state | Enable Security System Extension and forward System log | 30 days | service events do not prove collector identity | BH-020 |
| BH-TEL-09 | Microsoft Entra ID | SigninLogs, AADServicePrincipalSignInLogs | tenant, principal/app/service principal, source IP, auth method, result, correlation ID, resource | Route interactive and workload identity sign-ins to the SIEM | 30 days; correlate to API activity within 30 minutes | managed identity and service-principal schemas differ | BH-016 |
| BH-TEL-10 | Microsoft Graph activity logs | MicrosoftGraphActivityLogs | tenant, AppId, UserId and ServicePrincipalId (both normalized), source IP, method, full request URI, resource family, status, request/correlation ID | Enable and route Microsoft Graph activity logs; normalize resource family from URI | 30 days; distinct-family and pagination baselines | availability/licensing and field population vary | BH-016,017,019,020 |
| BH-TEL-11 | Azure control/read-plane audit or gateway | AzureActivity, AZURE_RESOURCE_READ | tenant/subscription, principal/app, source IP, operation, provider family, scope, status, correlation ID | Route AzureActivity and any available read-plane/gateway audit; document uncovered GET operations | 30 days; distinct-provider/scope baselines | AzureActivity does not guarantee every successful resource GET | BH-016,018–020 |

## Rule-by-rule requirements

| YARA-L rule | Procedures | Capability IDs | Minimum viable telemetry | Optional enrichment | Failure mode if absent |
| --- | --- | --- | --- | --- | --- |
| `bloodhound_collector_process_network_context` | BH-001 | BH-TEL-01,03 | process launch plus process-attributed LDAP/Graph/ARM connections | signer, prevalence, asset role | no match without process attribution and service classification |
| `bloodhound_ldap_directory_discovery_fanout` | BH-002,004 | BH-TEL-02 | LDAP query source and normalized object category | approved identity application, result count | category cardinality unavailable without parser enrichment |
| `bloodhound_sensitive_directory_attribute_reads` | BH-003,005 | BH-TEL-02 | requested LDAP attributes/controls or scoped access event | naming context, PKI class | standard DC logs usually omit requested attributes |
| `bloodhound_smb_rpc_host_sweep` | BH-006 | BH-TEL-03,05 | process-attributed destination IP and integer port (135/139/445), internal-range enrichment, stable process; 30-minute window | scanner inventory (`approved_scanner`, fails open) | network-only source cannot distinguish processes (BH-DR-30) |
| `bloodhound_remote_session_registry_collection` | BH-007,008 | BH-TEL-04,06 | RPC operation label naming NetSessionEnum/SRVSVC, NetWkstaUserEnum/WKSSVC or remote registry, with source and target | logon/share context | generic SMB authentication loses operation specificity; endpoint registry telemetry on the target cannot supply the source (BH-DR-29) |
| `bloodhound_samr_local_group_enumeration` | BH-009,010 | BH-TEL-04 | SAMR/LSA operation and source-to-target identity | group/right criticality | unavailable in normal Windows events |
| `bloodhound_sysvol_policy_file_collection` | BH-011 | BH-TEL-05,07 | source and multiple SYSVOL policy paths (path-segment anchored) within 30 minutes | process identity, normal GPO refresh baseline | 5140 alone lacks paths; EDR may omit remote reads (BH-DR-31) |
| `bloodhound_remote_security_configuration_reads` | BH-012 | BH-TEL-04,06 | complete sensitive registry path, source and target | posture-scanner identity | Sysmon changes do not cover reads |
| `bloodhound_service_protocol_probe_fanout` | BH-013 | BH-TEL-03 | process-attributed connection target with a `service_family` label (webdav/smb/ldap/ldaps) | scanner/asset role | without the service-family label the rule cannot match; broad/noisy without process and role context (BH-DR-30) |
| `bloodhound_recurrent_collection_activity` | BH-014 | BH-TEL-01,02,04,06 | stable process entity, target breadth, four-hour retention and **required** process prevalence (`rare`) | scheduled-job baseline | silent without prevalence enrichment (BH-DR-32); PID reuse or missing targets invalidates correlation |
| `bloodhound_collection_archive_creation` | BH-015 | BH-TEL-07 | same host and process: multiple JSON/CSV creates plus an archive create within 10 minutes | delete events, hashes | no archive or memory-only output is missed (BH-DR-28) |
| `bloodhound_azure_authentication_context` | BH-016 | BH-TEL-09–11 | sign-in plus same-principal and application Graph or ARM reads within 60 minutes | correlation ID, app inventory | workload principal mapping may not join (BH-DR-27) |
| `bloodhound_azure_graph_enumeration_fanout` | BH-017 | BH-TEL-10 | Graph GET resource-family enrichment | pagination and app baseline | rule cannot calculate breadth without Graph activity logs |
| `bloodhound_azure_resource_enumeration_fanout` | BH-018 | BH-TEL-11 | ARM provider-family and scope reads | CSPM inventory | AzureActivity alone may omit successful GETs |
| `bloodhound_azure_rbac_enumeration` | BH-019 | BH-TEL-10,11 | normalized RBAC/owner/access-policy operation and scope | role criticality | product event type alone is insufficient |
| `bloodhound_cloud_collection_output` | BH-020 | BH-TEL-01,07–11 | same user/host cloud reads plus JSON or service effect | stable process and cloud correlation ID | host/user join can still overlap on shared systems |
| `bloodhound_process_to_directory_effect` | BH-001 | BH-TEL-02 | endpoint-attributed LDAP_SEARCH with host, stable process entity and search base DN or result object | process path, signer, account | cloud audit cannot join to a process; without EDR LDAP attribution the rule is silent |
| `bloodhound_ldap_deep_single_category_enumeration` | BH-002,004 | BH-TEL-02 | LDAP_SEARCH/1644 expanded to per-result object identity plus naming context, client host and account; 4-hour retention | DC identity for distribution context | summary-only query events never reach the distinct-object threshold (accepted gap BH-DR-10) |
| `bloodhound_samr_alias_membership_fanout` | BH-009 | BH-TEL-04 | RPC_CALL resolving SAMR interface and alias operation by name or UUID+opnum, with source and target host | account and process attribution | unavailable in native Windows events; opnum-only sensors require UUID normalization |
| `bloodhound_remote_security_configuration_value_reads` | BH-012 | BH-TEL-06 | EDR REGISTRY_READ with full key path, value name, subject account, reading process and target host | RemoteRegistry service state, logon type | 4656/4663 omit the value name and Sysmon records changes not reads; without EDR value-level read telemetry the rule is silent (BH-DR-25) |
| `bloodhound_graph_deep_relationship_enumeration` | BH-017 | BH-TEL-10 | Graph activity GETs with full request URI, AppId and UserId or ServicePrincipalId | source IP, response status | without Graph activity logs, or with an unnormalized ServicePrincipalId, app-only collection is missed |

## Deployment order

1. Validate provider identity, event IDs and stable source/process fields.
2. Baseline approved identity governance, CSPM, inventory, scanner and policy-management systems.
3. Enable high-value RPC/registry/LDAP-sensitive-read effects where rich telemetry exists.
4. Tune cardinality and recurrence only after measuring complete collection health.
5. Keep every rule experimental until positive, negative, missing-event, reordered-event and boundary fixtures pass.

## Validation checklist

- [x] Every current YARA-L rule appears in the rule matrix.
- [ ] Provider/parser mappings verified in the target tenant.
- [ ] Required enrichment fields are populated.
- [ ] Retention supports every match window.
- [ ] Approved inventory/governance products are baselined.
- [ ] Collection health and missing-source behavior are monitored.

## Unresolved telemetry gaps

- NetSessionEnum, SAMR and LSA read operations require vendor/NDR RPC visibility for specific detection.
- LDAP requested-attribute and object-category fields require directory/EDR enrichment beyond default Security logs.
- Microsoft Graph activity and Azure read-plane coverage must be confirmed; AzureActivity is not assumed complete for GET enumeration.
- Per-result LDAP object identity is an uncommon parser capability; `bloodhound_ldap_deep_single_category_enumeration` remains dependent on it (BH-DR-10, accepted gap).
- Cloud audit logs carry no endpoint process identity, so process-to-directory attribution is endpoint-LDAP only (BH-DR-17).
