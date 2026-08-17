# Rubeus translation review

- Canonical rules: 12 YARA-L rules under `detections/rubeus/yaral/`.
- Secondary drafts reviewed: 60 files; 12 each in SPL, KQL, SQL, Elastic EQL, and Sigma.
- Parity: complete by basename and source linkage.
- Fidelity: all `partial`; none claim equivalence or validation.
- Shared backend limitations: `schemas/splunk-cim.yml`, `schemas/sentinel-asim.yml`, `schemas/normalized-sql.yml`, `schemas/elastic-ecs.yml`, and `schemas/sigma.yml`.
- Tool-specific exceptions: absence-based ticket-use logic requires complete KDC coverage and backend-specific state; other exceptions are recorded per rule.
- Required follow-up: map the declared schema for each backend, implement the canonical logic natively, compile, and test positive, negative, reordered, missing-event, and boundary-window fixtures before use.
