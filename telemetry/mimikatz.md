# mimikatz telemetry requirements

## Scope

- Tool revision: `306bc6b43099c7b698f2898401fddbded6a630c8`
- Detection files: 19 one-rule-per-file detections under `detections/mimikatz/yaral/`
- Generated/reviewed: 2026-08-16
- Status: `complete_for_experimental_rules`

## Consolidated collection plan

| Capability ID | Provider / product | Events / IDs | Required fields | Enablement / configuration | Retention / correlation | Known gaps | Supports |
| --- | --- | --- | --- | --- | --- | --- | --- |
| TEL-001 | Sysmon and EDR process telemetry | process launch/open/injection/module/driver | source and target process entities, paths, signer, user, access mask, operation, parent | Enable Process Access, tamper/injection, driver and module telemetry | Retain 7 days and preserve stable process entity IDs | Standard logs do not expose memory contents; vendor event types differ | P02â€“P09, P13, P22, P27â€“P28, P32, P40, P43â€“P45 |
| TEL-002 | Windows Security and domain controllers | 4624, 4656, 4662, 4663, 472x, 5136 and replication events | subject/logon ID, source host/IP, object/path, access rights/GUID, target identity | Enable Logon, Object Access, Directory Service Access/Changes and account-management auditing with scoped SACLs | Retain 30 days for identity baselining | SACLs and localization affect visibility; directory events can be high volume | P12, P14â€“P16, P29 |
| TEL-003 | EDR file and registry telemetry | sensitive file/registry read, create, delete and mutation | process entity, user, target path/key/value, operation, result | Enable read telemetry for credential/key stores and protected registry paths | Retain 7â€“30 days according to store sensitivity | Many sensors collect writes but not reads; offline copies may evade live registry logs | P12, P18â€“P21, P23â€“P25, P33, P37, P41, P46 |
| TEL-004 | Service, driver, print and event-log providers | 7045, 4697, 1102, service/driver/print changes | actor, host, service/driver/module, image path, signer, target log/provider | Forward System, Security, PrintService and driver/module telemetry | Retain 30 days | Provider enablement and event schemas vary | P06, P26, P36, P43â€“P45 |
| TEL-005 | EDR device, firmware, clipboard and named-pipe telemetry | device/firmware access, clipboard read, pipe/RPC operations | process entity, user, device or pipe, operation, peer, result | Enable advanced device, clipboard, firmware and IPC telemetry where supported | Retain 7 days | Mostly vendor-specific and sometimes unavailable | P34â€“P35, P38â€“P39, P42â€“P43 |
| TEL-006 | Network, DNS, LDAP and RPC sensors | network connection, LDAP query, RPC interface | process/source, destination, protocol/interface, LDAP filter, account | Collect east-west DNS/LDAP/RPC and process-attributed network telemetry | Retain 14 days | Encryption and dynamic RPC ports reduce visibility | P14â€“P16, P30, P35, P38 |

## Rule-by-rule requirements

| YARA-L rule | Procedures | Capability IDs | Minimum viable telemetry | Optional enrichment | Failure mode if absent |
| --- | --- | --- | --- | --- | --- |
| `mimikatz_account_secret_change` | P16 | See consolidated plan by event/provider | DC Security 4723, 4724 and 4742 with caller, target and source context. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `mimikatz_certificate_key_operation` | P21,P24 | See consolidated plan by event/provider | AD CS, CAPI2, Hello, TPM or EDR key-operation telemetry. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `mimikatz_clipboard_device_access` | P34,P42 | See consolidated plan by event/provider | EDR clipboard or device-control telemetry with process and device or operation. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `mimikatz_cross_process_tamper` | P22,P27,P28,P32,P40 | See consolidated plan by event/provider | EDR process tamper telemetry normalized with source and target processes and operation. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `mimikatz_directory_mutation` | P15,P29 | See consolidated plan by event/provider | Domain controller 4662 and 5136 events normalized with subject, object, attribute and source. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `mimikatz_directory_network_discovery` | P30 | See consolidated plan by event/provider | LDAP, RPC or EDR discovery telemetry with process, account, destination and operation. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `mimikatz_directory_replication_right_access` | P14 | See consolidated plan by event/provider | Normalize domain-controller Security Event ID 4662 with subject, source host, object, access mask, and replication-right GUIDs. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `mimikatz_event_log_impairment` | P26 | See consolidated plan by event/provider | Forwarded Security 1102, System 104 or EDR service-tamper telemetry. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `mimikatz_firmware_driver_operation` | P39,P43 | See consolidated plan by event/provider | EDR firmware or driver telemetry and Code Integrity events with process and module identity. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `mimikatz_kerberos_activity` | P10 | See consolidated plan by event/provider | DC 4768-4771 and vendor LSA ticket-operation telemetry. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `mimikatz_lsass_memory_access` | P07,P09,P13 | See consolidated plan by event/provider | Normalize Sysmon Event ID 10 or equivalent EDR process-open telemetry to UDM with source and target process paths and access-mask text. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `mimikatz_process_file_context` | P01,P31,P33 | See consolidated plan by event/provider | Process creation and EDR file create telemetry with ancestry, signer and path. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `mimikatz_protected_sam_system_access_sequence` | P12 | See consolidated plan by event/provider | Normalize Windows 4656/4663 or EDR sensitive-registry read events; preserve process ID, host, registry path, and access operation. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `mimikatz_rpc_pipe_activity` | P35,P38 | See consolidated plan by event/provider | Sysmon 17/18 or EDR RPC and network telemetry with process, endpoint and peer. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `mimikatz_sensitive_store_access` | P18,P19,P20,P23,P25,P37,P41,P46 | See consolidated plan by event/provider | EDR sensitive file or registry read telemetry with process and target path. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `mimikatz_service_driver_module_change` | P06,P36,P44,P45 | See consolidated plan by event/provider | Security 4697, System 7045, Sysmon driver/image load and registry change telemetry. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `mimikatz_token_process_control` | P02,P03,P04,P05 | See consolidated plan by event/provider | EDR token and process-control telemetry with source, target, user and operation. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `mimikatz_sensitive_store_multi_family_access` | P18,P19,P20,P23,P25,P37,P41,P46 | See consolidated plan by event/provider | Same-process file/registry read telemetry across at least two independent credential-store families (Credential Manager/Vault vs. crypto/certificate/Hello/IIS/SCCM/Citrix/RDM), with process ID, host and user preserved. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match, or degrades to single-family confidence, when read telemetry for one family is absent or the process identifier is not stable |
| `mimikatz_module_load_into_lsass_or_spooler` | P06,P36,P44,P45 | See consolidated plan by event/provider | Sysmon Event ID 7 (or equivalent EDR image/module-load telemetry) normalized with the loading process image path. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match when Image Load telemetry is disabled, unmapped, or the sensor represents the loading process differently |

## Deployment order

1. Collect and validate the foundational identity, process and network sources before enabling correlations.
2. Verify every parser field referenced by a rule using representative sanitized events.
3. Enable high-confidence effect/sequence rules, then baseline cardinality and rarity rules.
4. Enable vendor-specific EDR/API rules only where the required event mapping is confirmed.
5. Review collection health continuously; missing sources must degrade coverage explicitly.

## Validation checklist

- [x] Every current YARA-L rule appears in the rule matrix.
- [ ] Provider/parser mappings were verified in the target tenant.
- [ ] Required fields are populated in representative events.
- [ ] Retention supports every correlation window and absence check.
- [ ] Missing-source behavior and compensating signals were tested.
- [ ] Collection volume, privacy, and access controls were reviewed.

## Unresolved telemetry gaps

- Rules remain experimental until tenant-specific parser mappings and representative fixtures are validated.
- Vendor-specific EDR events must not be assumed present; disable dependent rules when the mapping is unavailable.
- Offline or memory-only procedures may have no direct event and require the compensating signals documented in the coverage ledger and detection review.

