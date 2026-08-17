# impacket telemetry requirements

## Scope

- Tool revision: `c23b3d55bc846a2460a459437601a94bfd25a269`
- Detection files: 20 one-rule-per-file detections under `detections/impacket/yaral/`
- Generated/reviewed: 2026-08-15
- Status: `complete_for_experimental_rules`

## Consolidated collection plan

| Capability ID | Provider / product | Events / IDs | Required fields | Enablement / configuration | Retention / correlation | Known gaps | Supports |
| --- | --- | --- | --- | --- | --- | --- | --- |
| TEL-001 | Windows Security/System and EDR | 4624, 4672, 4688, 4697, 5140, 5145, 7045 and process/file/network events | source IP, account/logon ID, host, share/path, service image, process lineage, signer | Enable Logon, Process Creation, Detailed File Share and service auditing; collect EDR process/file/network | Retain 30 days; correlate source and target by account/logon/time | High-volume management activity overlaps and cross-host IDs may not join | IMP-01â€“05, IMP-07â€“08, IMP-13â€“16, IMP-18, IMP-22 |
| TEL-002 | Task Scheduler and WMI providers | TaskScheduler 100/106/141/200, Security 4698/4699, WMI Activity 5857â€“5861 | task name/action, account, host, client process, namespace, operation, child process | Enable and forward TaskScheduler and WMI Activity Operational logs | Retain 14 days | IDs/fields vary by OS; outputless execution lacks SMB artifacts | IMP-04â€“06 |
| TEL-003 | Domain controllers and directory services | 4768, 4769, 4662, 5136 and LDAP queries | source, account, object/GUID, attribute, filter, service, ticket options/result | Enable Kerberos and Directory Service Access/Changes with scoped SACLs | Retain 30 days | Encrypted LDAP and missing SACLs create gaps | IMP-09â€“11, IMP-13 |
| TEL-004 | Network IDS/NDR, firewall and endpoint sockets | SMB, RPC/DCOM, LDAP, MSSQL, mail, raw socket, ICMP, capture/listener events | source/destination, port, protocol/interface, process, account, bytes and direction | Collect east-west protocol metadata and endpoint socket listen/connect telemetry | Retain 14 days | Encryption/dynamic RPC ports and missing process identity reduce attribution | IMP-02, IMP-05, IMP-08, IMP-15â€“19, IMP-21â€“22 |
| TEL-005 | Application and service audit | MSSQL, Exchange/mail, Terminal Services and remote registry | authenticated principal, source, action/query, target object, result | Enable product-native audit and centralize service logs | Retain 30 days | Coverage differs by product; Exchange source remains blocked in this revision | IMP-14â€“18 |
| TEL-006 | EDR sensitive-store and artifact telemetry | credential store/hive/database reads and local artifact conversion | process, user, target path/object, operation, result | Enable sensitive file/registry reads and artifact lifecycle telemetry | Retain 14 days | Offline parsing/conversion is not uniquely observable | IMP-12â€“14, IMP-20 |

## Rule-by-rule requirements

| YARA-L rule | Procedures | Capability IDs | Minimum viable telemetry | Optional enrichment | Failure mode if absent |
| --- | --- | --- | --- | --- | --- |
| `impacket_ad_authorization_change` | IMP-10 | See consolidated plan by event/provider | DC 5136/5137 with DN, attribute, actor and old/new values. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `impacket_cross_source_ntlm_relay` | IMP-21 | See consolidated plan by event/provider | Normalized NTLM authentication with account, source, destination and result. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `impacket_packet_capture_or_raw_socket` | IMP-19 | See consolidated plan by event/provider | EDR process, driver and raw-socket telemetry. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `impacket_privilege_path_effects` | IMP-22 | See consolidated plan by event/provider | DC directory-change and Kerberos events with actor, target and source. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `impacket_rapid_scheduled_task_create_and_run` | IMP-04 | See consolidated plan by event/provider | Normalize Task Scheduler Operational or Security 4698/4699 events with task name, host, action, user, and timestamp. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `impacket_remote_account_or_group_change` | IMP-07 | See consolidated plan by event/provider | DC Security identity-change and 4624 events with actor and source. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `impacket_remote_registry_activity` | IMP-14 | See consolidated plan by event/provider | Service, registry and RPC telemetry with key, actor and source. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `impacket_remote_rpc_discovery` | IMP-08,IMP-16 | See consolidated plan by event/provider | RPC-aware network or ETW telemetry with source, target and interface UUID. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `impacket_remote_service_binary_sequence` | IMP-03 | See consolidated plan by event/provider | Normalize Windows 5145 plus 7045/4697 or EDR file/service events with target host, account, source IP, service path, and timestamps. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `impacket_remote_wmi_activity` | IMP-05 | See consolidated plan by event/provider | Normalize WMI Activity or EDR process creation with host, account, parent process, child process, and command line. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `impacket_sensitive_file_or_replication_access` | IMP-13 | See consolidated plan by event/provider | DC 4662 and SMB/object events with access GUID, actor, source and path. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `impacket_sensitive_ldap_search` | IMP-09 | See consolidated plan by event/provider | LDAP diagnostic 1644 or directory audit preserving filter and requested attributes. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `impacket_short_lived_command_service` | IMP-03 | See consolidated plan by event/provider | Normalize Windows 7045 or 4697 service-install events and preserve the full service image path. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `impacket_smb_sensitive_file_activity` | IMP-01,IMP-13 | See consolidated plan by event/provider | Windows 5145/4663 or EDR SMB file events with source, account, share, path and access. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `impacket_suspicious_kerberos_requests` | IMP-11 | See consolidated plan by event/provider | DC 4768/4769/4771 with client, account, service, encryption and options. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `impacket_suspicious_service_control` | IMP-03 | See consolidated plan by event/provider | Windows 4624 and 4697/7045 with host, account and source. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `impacket_terminal_services_control` | IMP-18 | See consolidated plan by event/provider | Terminal Services Operational and Security session events with actor and session. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `impacket_unusual_protocol_listener` | IMP-02 | See consolidated plan by event/provider | EDR network-listen events with process, host, port and direction. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `impacket_unusual_service_authentication` | IMP-15 | See consolidated plan by event/provider | Application authentication and network logs with service, source, account and result. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `impacket_wmi_subscription_change` | IMP-06 | See consolidated plan by event/provider | Sysmon 19-21 or equivalent WMI repository events. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |

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

