# sliver telemetry requirements

## Scope

- Tool revision: `13c2d3344927429cf55f6f7212499087e804bf47`
- Detection files: 21 one-rule-per-file detections under `detections/sliver/yaral/` (13 original plus 8 compensating rules added while draining the `deferred_pending_rule_improvement_run` public-comparison backlog on 2026-08-16; 3 of the original 13 were also rewritten in place on the same date)
- Generated/reviewed: 2026-08-15; updated 2026-08-16
- Status: `complete_for_experimental_rules`

## Consolidated collection plan

| Capability ID | Provider / product | Events / IDs | Required fields | Enablement / configuration | Retention / correlation | Known gaps | Supports |
| --- | --- | --- | --- | --- | --- | --- | --- |
| TEL-001 | EDR process and network telemetry | process launch/termination, connect/listen | stable process entity/PID, parent, image, signer, user, destination, port, direction | Enable process-attributed connect and listen telemetry on all supported platforms | Retain at least 7 days; correlate by stable process entity | PID reuse and missing process attribution weaken joins | PROC-001â€“005, PROC-010, PROC-021â€“022, PROC-026 |
| TEL-002 | DNS, proxy, TLS and firewall | DNS, HTTP/S, TLS and UDP flows | source process/host, query, destination, SNI, certificate, method/URI, bytes, timing | Centralize endpoint and network egress metadata | Retain 14 days for prevalence and recurrence baselines | Encrypted/custom transports and destination churn reduce specificity | PROC-002â€“005, PROC-021 |
| TEL-003 | EDR file, registry and memory telemetry | file read/write/delete, registry change, process access/injection/memory load | process entity, target, operation, path/key, signer, user | Enable file lifecycle, registry, process-tamper and memory telemetry | Retain 7 days | Memory-only and vendor-specific operations may be unavailable | PROC-007â€“012, PROC-015, PROC-018, PROC-026 |
| TEL-004 | Windows/Linux/macOS identity and execution logs | logon, privilege, service, task, SSH and command execution | account, source, host, parent/child, service/task/action, result | Enable platform authentication, process, service/task and SSH auditing | Retain 30 days for administrative baselines | Cross-platform schemas and remote causality differ | PROC-010, PROC-016â€“020 |
| TEL-005 | EDR collection sensors | screen capture and collection events | process entity, user/session, collection type, bytes and subsequent egress | Enable vendor screen/collection telemetry if available | Retain 7 days | Standard OS logs often do not expose capture; rule must be disabled without verified mapping | PROC-013â€“014 |

## Rule-by-rule requirements

| YARA-L rule | Procedures | Capability IDs | Minimum viable telemetry | Optional enrichment | Failure mode if absent |
| --- | --- | --- | --- | --- | --- |
| `sliver_browser_debugging_from_network_process` | PROC-022 | See consolidated plan by event/provider | Process launch with command line, plus a distinct child listen-socket event and parent egress, all sharing host and parent/child PID | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `sliver_cleanup_after_egress` | PROC-002,PROC-026 | See consolidated plan by event/provider | File deletion and network telemetry with stable PID | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `sliver_self_delete_after_egress` | PROC-002,PROC-026 | See consolidated plan by event/provider | File-deletion and network telemetry that both carry the process file SHA-256, sharing stable PID | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match, or degrades to the broader `sliver_cleanup_after_egress` signal, when file hash is absent from one or both event types |
| `sliver_dns_or_udp_process_egress` | PROC-004 | See consolidated plan by event/provider | Process-attributed DNS or UDP network telemetry | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `sliver_low_and_slow_udp_beacon` | PROC-004 | See consolidated plan by event/provider | Process-attributed DNS or UDP network telemetry with destination, port, and per-event timestamp | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match, or loses periodicity fidelity, when destination/port are not populated per event |
| `sliver_file_activity_from_network_process` | PROC-007,PROC-008,PROC-009 | See consolidated plan by event/provider | EDR file and network telemetry sharing stable PID | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `sliver_credential_file_access_from_network_process` | PROC-007,PROC-008 | See consolidated plan by event/provider | EDR file read/creation telemetry with full path, plus network telemetry, sharing stable PID | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match when full path is not populated or the sensor does not emit read/creation events for the target paths |
| `sliver_identity_or_service_from_network_process` | PROC-016,PROC-017,PROC-019 | See consolidated plan by event/provider | Windows identity/service and process network telemetry normalized by host and account | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `sliver_explicit_credential_service_creation` | PROC-016,PROC-017,PROC-019 | See consolidated plan by event/provider | Windows 4648 explicit-credential logon and 4697/7045 service-creation events correlated by target account and host, plus network telemetry | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match when 4648 auditing is not enabled or account fields are not normalized consistently between event types |
| `sliver_listener_with_egress` | PROC-005,PROC-021 | See consolidated plan by event/provider | EDR socket listen and process network events with stable PID | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `sliver_relay_to_novel_destination` | PROC-005,PROC-021 | See consolidated plan by event/provider | EDR/firewall inbound-accept and outbound-connect events sharing stable PID, with source and destination IP | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match when inbound acceptance (not just listen state) is not separately observable |
| `sliver_parent_egress_with_spawned_interpreter` | PROC-010 | See consolidated plan by event/provider | Process and network events with parent PID | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `sliver_process_access_from_network_process` | PROC-011,PROC-012,PROC-015 | See consolidated plan by event/provider | Tenant-verified EDR process access/injection/memory event plus stable PID network telemetry | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `sliver_lsass_access_from_network_process` | PROC-011,PROC-012,PROC-015 | See consolidated plan by event/provider | Tenant-verified process-access event (for example Sysmon 10) with target process path and access mask, plus network telemetry | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match when the sensor does not expose an access-mask-equivalent field or does not identify the target process image |
| `sliver_process_behavior_cluster` | PROC-001 | See consolidated plan by event/provider | Process launch and process network UDM with stable PID | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `sliver_unsigned_process_novel_egress` | PROC-001 | See consolidated plan by event/provider | Process launch with code-signature verification status, plus network telemetry with destination | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match when signature-verification status is not populated; signed implant builds are a known false-negative path and remain covered only by the broader `sliver_process_behavior_cluster` rule |
| `sliver_recurrent_process_egress` | PROC-002,PROC-003 | See consolidated plan by event/provider | Process-attributed network events with stable process entity and destination, aggregated by minute | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `sliver_registry_from_network_process` | PROC-018 | See consolidated plan by event/provider | Registry mutation and network UDM with stable PID | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `sliver_registry_persistence_key_from_network_process` | PROC-018 | See consolidated plan by event/provider | Registry mutation telemetry with full key path, plus network telemetry, sharing stable PID | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match when full registry key path is not populated |
| `sliver_remote_admin_sequence` | PROC-020 | See consolidated plan by event/provider | Windows Security 4624 (TargetLogonId) and 4697 (SubjectLogonId) normalized to `network.session_id`, or SSH authentication and command events sharing a session identifier, with target host and account | signer, prevalence, asset role, approved source/account and maintenance window | The rule cannot match unless both events carry the same normalized session identifier. System 7045 carries no logon identifier and is excluded from this rule (REVIEW-015); 7045-only installs depend on `sliver_identity_or_service_from_network_process` and `sliver_explicit_credential_service_creation` |
| `sliver_screen_capture_process_egress` | PROC-014 | See consolidated plan by event/provider | Verified EDR screen capture mapping and stable PID network telemetry | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |

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

