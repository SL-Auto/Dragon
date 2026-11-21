# Rubeus procedure summary

Generated context view. Use the coverage ledger and cited report as authoritative evidence.

- Tool ID: rubeus
- Revision: 74215f68ea70bd6a66c008da91bf5fe21d20b154
- Lifecycle: analyzed
- Full evidence: RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md
- Coverage ledger: coverage/rubeus.yml

| Procedure | Summary | Telemetry | Detection | Canonical rules |
| --- | --- | --- | --- | --- |
| PROC-001 | AS/TGT acquisition and authentication probing | assessed | detected | rubeus_as_request_anomaly, rubeus_as_request_failed_preauth_fanout, rubeus_kerberos_transport_from_unexpected_process |
| PROC-002 | TGS acquisition and renewal | assessed | detected | rubeus_service_ticket_or_renewal_anomaly, rubeus_rc4_service_ticket_fanout, rubeus_ticket_renewal_anomaly, rubeus_kerberos_transport_from_unexpected_process |
| PROC-003 | AS-REP roasting | assessed | detected | rubeus_asrep_roast_sequence, rubeus_asrep_single_account_sensitive, rubeus_kerberos_transport_from_unexpected_process |
| PROC-004 | Kerberoasting | assessed | detected | rubeus_kerberoast_sequence, rubeus_rc4_service_ticket_fanout, rubeus_kerberos_transport_from_unexpected_process |
| PROC-005 | S4U and delegation workflows | assessed | detected | rubeus_s4u_ticket_sequence, rubeus_kerberos_transport_from_unexpected_process |
| PROC-006 | Ticket cache and session discovery or extraction | assessed | detected | rubeus_lsa_ticket_cache_operations, rubeus_lsa_encoded_ticket_retrieval |
| PROC-007 | Ticket submission purge and net-only session | assessed | detected | rubeus_lsa_ticket_mutation, rubeus_netonly_ticket_sequence, rubeus_lsa_ticket_submission |
| PROC-008 | Ticket forging | assessed | detected | rubeus_ticket_use_without_credible_kdc_issue |
| PROC-009 | Ticket mutation | assessed | detected | rubeus_ticket_use_without_credible_kdc_issue |
| PROC-010 | Ticket parsing and conversion | assessed | detected | rubeus_ticket_artifact_access_or_creation |
| PROC-011 | Key derivation | not_observable | not_observable |  |
| PROC-012 | Password change | assessed | detected | rubeus_unusual_kerberos_password_change, rubeus_kerberos_transport_from_unexpected_process |
| PROC-013 | Alternate KDC transport and output artifacts | assessed | detected | rubeus_kerberos_over_http_proxy, rubeus_ticket_artifact_access_or_creation |
