# Rubeus translation review

- Canonical rules: 19 YARA-L rules under `detections/rubeus/yaral/`.
- Secondary drafts reviewed: 95 files; 19 each in SPL, KQL, SQL, Elastic EQL, and Sigma.
- Parity: complete by basename and source linkage.
- Fidelity: generator drafts are `partial`; the four rules in the 2026-11-21 exceptions are `high` or `partial` as listed. None claim equivalence or validation.
- Shared backend limitations: `schemas/splunk-cim.yml`, `schemas/sentinel-asim.yml`, `schemas/normalized-sql.yml`, `schemas/elastic-ecs.yml`, and `schemas/sigma.yml`.
- Tool-specific exceptions: absence-based ticket-use logic requires complete KDC coverage and backend-specific state; other exceptions are recorded per rule.
- Required follow-up: map the declared schema for each backend, implement the canonical logic natively, compile, and test positive, negative, reordered, missing-event, and boundary-window fixtures before use.

## 2026-11-21 exceptions — four rules

- Native translations were rendered from per-rule specs mirroring the revised YARA-L: `rubeus_lsa_encoded_ticket_retrieval`, `rubeus_lsa_ticket_submission`, `rubeus_rc4_service_ticket_fanout` and `rubeus_ticket_renewal_anomaly`.
  - **SPL, KQL, SQL and Sigma:** `high`. These are single-event aggregations, expressed natively in SPL/KQL/SQL and with `value_count`/`event_count` correlations in Sigma.
  - **EQL:** `partial`, because it cannot aggregate.
- The LSA rules assume a vendor EDR API table exposing `api_name`, `kerberos_message_type`, `result` and `target_luid` (REVIEW-003).
- `high` means the canonical logic is expressed natively in the target. It does not mean equivalent or validated: column names are tenant assumptions.

## 2026-11-21 exceptions — comparison backlog resolution

- `rubeus_as_request_failed_preauth_fanout` moved from generator candidate retrieval to native specs. `rubeus_asrep_single_account_sensitive` and `rubeus_kerberos_transport_from_unexpected_process` are new and rendered natively (`scripts/native_translations/specs_ri.py`).
  - **SPL, KQL, SQL and Sigma:** `high`.
  - **EQL:** `partial`, because it cannot aggregate.
- The transport rule expresses the canonical `not lsass.exe` exclusion as a negated regex in every backend. Approved non-LSA Kerberos clients remain a tenant allowlist.
- The generator drafts for `rubeus_kerberoast_sequence`, `rubeus_lsa_ticket_cache_operations`, `rubeus_lsa_ticket_mutation`, `rubeus_ticket_artifact_access_or_creation`, `rubeus_s4u_ticket_sequence` and `rubeus_ticket_use_without_credible_kdc_issue` were regenerated after canonical fixes (REVIEW-010, 011, 013). They remain `partial` candidate retrieval: the S4U inventory marker, the domain-joined health gate and the `!$tgs` absence are not expressed in these drafts.
