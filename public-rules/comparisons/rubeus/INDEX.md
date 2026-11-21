# Rubeus public-rule comparison index

Pinned Rubeus revision: `74215f68ea70bd6a66c008da91bf5fe21d20b154`

All 12 canonical Rubeus rules were compared from a threat-detection perspective. Every comparison ends in a terminal `accept`, `modify` or `reject` decision; accepted and modified proposals were implemented in canonical YARA-L after adversarial review, with full downstream regeneration. Rules added by later passes are covered through the comparison whose branch they close.

| Internal rule | Procedure | Headline conclusion | Decision |
| --- | --- | --- | --- |
| [rubeus_as_request_anomaly](./rubeus_as_request_anomaly.md) | PROC-001 | complementary, ours_stronger, public_stronger | modify |
| [rubeus_asrep_roast_sequence](./rubeus_asrep_roast_sequence.md) | PROC-003 | ours_stronger, public_stronger | modify |
| [rubeus_kerberoast_sequence](./rubeus_kerberoast_sequence.md) | PROC-004 | complementary, ours_stronger, public_stronger | modify |
| [rubeus_kerberos_over_http_proxy](./rubeus_kerberos_over_http_proxy.md) | PROC-013 | insufficient_evidence, ours_stronger, public_stronger | modify |
| [rubeus_lsa_ticket_cache_operations](./rubeus_lsa_ticket_cache_operations.md) | PROC-006 | complementary, different_scope, equivalent | modify |
| [rubeus_lsa_ticket_mutation](./rubeus_lsa_ticket_mutation.md) | PROC-007 | ours_stronger, public_stronger | modify |
| [rubeus_netonly_ticket_sequence](./rubeus_netonly_ticket_sequence.md) | PROC-007 | different_scope, ours_stronger, public_stronger | reject |
| [rubeus_s4u_ticket_sequence](./rubeus_s4u_ticket_sequence.md) | PROC-005 | ours_stronger, public_stronger | modify |
| [rubeus_service_ticket_or_renewal_anomaly](./rubeus_service_ticket_or_renewal_anomaly.md) | PROC-002 | ours_stronger, public_stronger | modify |
| [rubeus_ticket_artifact_access_or_creation](./rubeus_ticket_artifact_access_or_creation.md) | PROC-008,PROC-009,PROC-010,PROC-013 | insufficient_evidence, ours_stronger, public_stronger | modify |
| [rubeus_ticket_use_without_credible_kdc_issue](./rubeus_ticket_use_without_credible_kdc_issue.md) | PROC-008,PROC-009 | complementary, ours_stronger | modify |
| [rubeus_unusual_kerberos_password_change](./rubeus_unusual_kerberos_password_change.md) | PROC-012 | equivalent, insufficient_evidence, public_stronger | modify |

## Cross-rule findings

- Strongest internal signals: direct LSA ticket submit/retrieve operations, same-LUID Type 9 plus ticket submission, no-preauthentication AS requests, and resource-side PAC/identity anomalies.
- Weakest internal signals: generic 4769/4770 volume, filename/extension matches, ordinary multi-target password changes, and S4U fan-out without an implemented delegation-edge baseline.
- Material missing branches: targeted single-account roasting, ticket encryption/options and requester-to-service novelty, process attribution for Kerberos-over-HTTP, caller trust and success for LSA operations, resource-side confirmation after ticket submission, and collection-health gating for KDC-issuance absence.
- Public rules are strongest where they add ticket-property specificity, first-seen relationships, PowerShell API-content coverage, rare NewCredentials process context, or risky delegation configuration. They are weaker where they are backend/product-specific, implementation-specific, RC4-only, or simply forward opaque vendor alerts.

## Unmatched public scope

No Chronicle community rule in the pinned public corpus materially matched these Rubeus procedure branches. Public rules for unrelated Kerberos attacks or configuration states were excluded unless they supplied a defensible compensating branch.

## Review status

Threat-detection comparison complete for 12/12 Rubeus rules. Canonical improvements are explicitly deferred to a separate rule-change run so external logic is not adopted blindly.
