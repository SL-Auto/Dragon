# rubeus telemetry requirements

## Scope

- Tool revision: `74215f68ea70bd6a66c008da91bf5fe21d20b154`
- Detection files: 17 one-rule-per-file detections under `detections/rubeus/yaral/`
- Generated/reviewed: 2026-08-15
- Status: `complete_for_experimental_rules`

## Consolidated collection plan

| Capability ID | Provider / product | Events / IDs | Required fields | Enablement / configuration | Retention / correlation | Known gaps | Supports |
| --- | --- | --- | --- | --- | --- | --- | --- |
| TEL-001 | Windows domain controllers / Security log | 4768, 4769, 4770, 4771 | account, source IP/host, service/SPN, result, ticket options, pre-auth and encryption types | Enable Kerberos Authentication Service and Service Ticket Operations success/failure auditing (4771 requires Kerberos Authentication Service failure auditing); centralize every DC | At least 24 hours online for long absence correlations; preserve event time | Parser fields vary; missing DCs invalidate absence logic | PROC-001â€“005, PROC-008â€“009, PROC-012 |
| TEL-002 | EDR API / endpoint sensor | LSA authentication-package calls and process lineage | caller image/entity, user, host, API name, Kerberos message type, target LUID | Enable vendor API/credential-access telemetry and retain raw events | Correlate by host, LUID and process entity for at least 30 minutes | Not available in standard Windows logs; vendor mappings differ | PROC-006â€“007 |
| TEL-003 | EDR, Sysmon, firewall and proxy | process launch, network connection, HTTP | process entity/path/signer, destination DC/proxy, port, HTTP Content-Type | Enable process-attributed network and HTTP header telemetry | Retain 24 hours; correlate process to DC/proxy events | Perimeter logs may lack process attribution; encrypted proxy inspection may be unavailable | PROC-001â€“005, PROC-012, PROC-013 |
| TEL-004 | EDR file telemetry | file read/create | process entity, user, full path, operation, signer | Enable file reads and creates for ticket/artifact locations | Retain at least 7 days | Memory-only operations and renamed artifacts are missed | PROC-008â€“010, PROC-013 |
| TEL-005 | Resource servers and identity analytics | Kerberos service use and PAC/identity anomalies | user, source, service, target, auth method, PAC validation result | Collect resource-side authentication and PAC validation where supported | Retain at least 24 hours aligned with complete DC logs | Absence is unsafe when DC logs are incomplete; PAC fields are product-specific | PROC-008â€“009 |

## Rule-by-rule requirements

| YARA-L rule | Procedures | Capability IDs | Minimum viable telemetry | Optional enrichment | Failure mode if absent |
| --- | --- | --- | --- | --- | --- |
| `rubeus_as_request_anomaly` | PROC-001 | See consolidated plan by event/provider | Normalize DC Security 4768 with source IP, target account, preauthentication type, result, and encryption type. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `rubeus_as_request_failed_preauth_fanout` | PROC-001 | TEL-001 | DC Security 4768 and 4771 with source IP, target account and Status/Result Code normalized to `additional.fields["Status"]` (or `security_result.action = BLOCK`) | password-audit and lockout-monitor source allowlist | Without 4771 failure auditing, wrong-password probing is invisible; without Status or action, the rule cannot match (REVIEW-012) |
| `rubeus_asrep_roast_sequence` | PROC-003 | See consolidated plan by event/provider | Normalize 4768 with source IP, account, and PreAuthType in the configured additional field. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `rubeus_asrep_single_account_sensitive` | PROC-003 | TEL-001 | DC Security 4768 with PreAuthType, Status, source IP and target account | **required for this rule**: account-risk enrichment `account_risk_tier = high`; TicketEncryptionType for triage | Without the risk enrichment the rule stays silent; single-account requests then depend on the base three-account rule (REVIEW-014) |
| `rubeus_kerberoast_sequence` | PROC-004 | See consolidated plan by event/provider | Normalize directory-side LDAP filters and 4769 with host, user, and service. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `rubeus_kerberos_over_http_proxy` | PROC-013 | See consolidated plan by event/provider | Normalize process-attributed HTTP request Content-Type and proxy destination. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `rubeus_lsa_ticket_cache_operations` | PROC-006 | See consolidated plan by event/provider | EDR must expose LsaCallAuthenticationPackage and Kerberos message type with process and target LUID. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `rubeus_lsa_ticket_mutation` | PROC-007 | See consolidated plan by event/provider | EDR must expose LsaCallAuthenticationPackage message type, caller process, user, host, and target LUID. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `rubeus_netonly_ticket_sequence` | PROC-007 | See consolidated plan by event/provider | Normalize 4624 LogonType and TargetLogonId plus EDR KerbSubmitTicketMessage target LUID. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `rubeus_s4u_ticket_sequence` | PROC-005 | TEL-001 | Normalize 4769 with requesting account, client/source, target service, transited services, ticket options, and delegation context. | delegation-edge inventory setting `delegation_edge_approved` and `delegation_inventory_evaluated = true` | Without the inventory only the two-target branch can fire (REVIEW-011) |
| `rubeus_service_ticket_or_renewal_anomaly` | PROC-002 | See consolidated plan by event/provider | Normalize DC Security 4769 and 4770 with account, source IP, service, result, and encryption type. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `rubeus_ticket_artifact_access_or_creation` | PROC-008,PROC-009,PROC-010,PROC-013 | See consolidated plan by event/provider | Normalize EDR file read/create events with process, user, path, extension, and signer. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `rubeus_ticket_use_without_credible_kdc_issue` | PROC-008,PROC-009 | TEL-001, TEL-005 | Complete 4769 telemetry, resource-side Kerberos service use with PAC/identity anomaly, and a COLLECTION_HEALTH event; the health and access events must both carry the AD domain in `target.administrative_domain` | none | Without the domain on both events the health gate cannot join and the rule cannot match (REVIEW-013) |
| `rubeus_unusual_kerberos_password_change` | PROC-012 | See consolidated plan by event/provider | Normalize account-management password-change events and process-attributed network connections to Kerberos password-change service where available. | signer, prevalence, asset role, approved source/account and maintenance window | Rule cannot match or loses causal/contextual strength when required fields are absent |
| `rubeus_kerberos_transport_from_unexpected_process` | PROC-001,002,003,004,005,012 | TEL-003 | Sysmon Event ID 3 or EDR NETWORK_CONNECTION with destination port (88, 464), host and initiating process image path | approved non-LSA Kerberos client inventory by path and signer | Without process attribution, client-side Kerberos traffic cannot be attributed; DC-side 4768/4769/4723/4724 rules remain (REVIEW-015) |
| `rubeus_lsa_encoded_ticket_retrieval` | PROC-006 | TEL-002 | EDR LsaCallAuthenticationPackage events with Kerberos message type, result, caller process ID, host and target LUID | caller logon LUID for cross-session comparison | standard Windows logs do not expose LSA package calls; no EDR API telemetry means no detection |
| `rubeus_lsa_ticket_submission` | PROC-007 | TEL-002 | EDR LsaCallAuthenticationPackage KerbSubmitTicket events with result, caller process ID, host and target LUID | approved ticket-broker inventory | same as above |
| `rubeus_rc4_service_ticket_fanout` | PROC-002,004 | TEL-001 | DC Security 4769 with TicketEncryptionType, Status, source IP, requesting account and service name from every DC | approved legacy-RC4 service enrichment (fails open) | missing DCs undercount fan-out; AES-only environments make RC4 requests rare and higher-signal |
| `rubeus_ticket_renewal_anomaly` | PROC-002 | TEL-001 | DC Security 4770 with source IP, account and service from every DC | renewal baseline per account | low-rate automatic renewal is indistinguishable from native LSA renewal (REVIEW-009) |

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

- 2026-11-21: LSA package-call rules depend on vendor EDR API telemetry (REVIEW-003). Low-rate tool auto-renewal is not separable from native renewal in 4770 (REVIEW-009).

- Rules remain experimental until tenant-specific parser mappings and representative fixtures are validated.
- Vendor-specific EDR events must not be assumed present; disable dependent rules when the mapping is unavailable.
- Offline or memory-only procedures may have no direct event and require the compensating signals documented in the coverage ledger and detection review.

