# Rubeus translation review

- Canonical rules: 17 YARA-L rules under `detections/rubeus/yaral/`.
- Secondary drafts reviewed: 85 files; 17 each in SPL, KQL, SQL, Elastic EQL, and Sigma.
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
