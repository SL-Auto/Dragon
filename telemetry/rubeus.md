# rubeus telemetry requirements

## Scope

- Tool revision: `74215f68ea70bd6a66c008da91bf5fe21d20b154`
- Detection files: 13 one-rule-per-file detections under `detections/rubeus/yaral/`
- Generated/reviewed: 2026-08-15
- Status: `complete_for_experimental_rules`

## Consolidated collection plan

| Capability ID | Provider / product | Events / IDs | Required fields | Enablement / configuration | Retention / correlation | Known gaps | Supports |
| --- | --- | --- | --- | --- | --- | --- | --- |
| TEL-001 | Windows domain controllers / Security log | 4768, 4769, 4770 | account, source IP/host, service/SPN, result, ticket options, pre-auth and encryption types | Enable Kerberos Authentication Service and Service Ticket Operations success/failure auditing; centralize every DC | At least 24 hours online for long absence correlations; preserve event time | Parser fields vary; missing DCs invalidate absence logic | PROC-001â€“005, PROC-008â€“009, PROC-012 |
| TEL-002 | EDR API / endpoint sensor | LSA authentication-package calls and process lineage | caller image/entity, user, host, API name, Kerberos message type, target LUID | Enable vendor API/credential-access telemetry and retain raw events | Correlate by host, LUID and process entity for at least 30 minutes | Not available in standard Windows logs; vendor mappings differ | PROC-006â€“007 |
| TEL-003 | EDR, Sysmon, firewall and proxy | process launch, network connection, HTTP | process entity/path/signer, destination DC/proxy, port, HTTP Content-Type | Enable process-attributed network and HTTP header telemetry | Retain 24 hours; correlate process to DC/proxy events | Perimeter logs may lack process attribution; encrypted proxy inspection may be unavailable | PROC-001â€“005, PROC-013 |
| TEL-004 | EDR file telemetry | file read/create | process entity, user, full path, operation, signer | Enable file reads and creates for ticket/artifact locations | Retain at least 7 days | Memory-only operations and renamed artifacts are missed | PROC-008â€“010, PROC-013 |
| TEL-005 | Resource servers and identity analytics | Kerberos service use and PAC/identity anomalies | user, source, service, target, auth method, PAC validation result | Collect resource-side authentication and PAC validation where supported | Retain at least 24 hours aligned with complete DC logs | Absence is unsafe when DC logs are incomplete; PAC fields are product-specific | PROC-008â€“009 |

## Rule-by-rule requirements

| YARA-L rule | Procedures | Capability IDs | Minimum viable telemetry | Optional enrichment | Failure mode if absent |
| --- | --- | --- | --- | --- | --- |
| `rubeus_as_request_anomaly` | PROC-001 | See consolidated plan by event/provider | Normalize DC Security 4768 with source IP, target account, preauthentication type, result, and encryption type. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `rubeus_as_request_failed_preauth_fanout` | PROC-001 | See consolidated plan by event/provider (TEL-001) | Normalize DC Security 4768 with source IP, target account, and a `security_result.action` (or equivalent 4768 Result Code) field distinguishing non-success outcomes. | signer, prevalence, asset role, approved source/account and maintenance window | Rule stays silent (false-negative-safe) rather than mis-firing if the parser does not populate `security_result.action` for 4768 |
| `rubeus_asrep_roast_sequence` | PROC-003 | See consolidated plan by event/provider | Normalize 4768 with source IP, account, and PreAuthType in the configured additional field. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `rubeus_kerberoast_sequence` | PROC-004 | See consolidated plan by event/provider | Normalize directory-side LDAP filters and 4769 with host, user, and service. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `rubeus_kerberos_over_http_proxy` | PROC-013 | See consolidated plan by event/provider | Normalize process-attributed HTTP request Content-Type and proxy destination. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `rubeus_lsa_ticket_cache_operations` | PROC-006 | See consolidated plan by event/provider | EDR must expose LsaCallAuthenticationPackage and Kerberos message type with process and target LUID. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `rubeus_lsa_ticket_mutation` | PROC-007 | See consolidated plan by event/provider | EDR must expose LsaCallAuthenticationPackage message type, caller process, user, host, and target LUID. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `rubeus_netonly_ticket_sequence` | PROC-007 | See consolidated plan by event/provider | Normalize 4624 LogonType and TargetLogonId plus EDR KerbSubmitTicketMessage target LUID. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `rubeus_s4u_ticket_sequence` | PROC-005 | See consolidated plan by event/provider | Normalize 4769 with requesting account, client/source, target service, transited services, ticket options, and delegation context. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `rubeus_service_ticket_or_renewal_anomaly` | PROC-002 | See consolidated plan by event/provider | Normalize DC Security 4769 and 4770 with account, source IP, service, result, and encryption type. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `rubeus_ticket_artifact_access_or_creation` | PROC-008,PROC-009,PROC-010,PROC-013 | See consolidated plan by event/provider | Normalize EDR file read/create events with process, user, path, extension, and signer. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `rubeus_ticket_use_without_credible_kdc_issue` | PROC-008,PROC-009 | See consolidated plan by event/provider | Centralize complete 4769 telemetry and resource-side Kerberos service-use/PAC anomaly data with normalized user, source, and service. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `rubeus_unusual_kerberos_password_change` | PROC-012 | See consolidated plan by event/provider | Normalize account-management password-change events and process-attributed network connections to Kerberos password-change service where available. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |

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

