# Sliver translation review

- Canonical rules: 14 YARA-L rules under `detections/sliver/yaral/`.
- Secondary drafts reviewed: 70 files; 14 each in SPL, KQL, SQL, Elastic EQL, and Sigma.
- Parity: complete by basename and source linkage.
- Fidelity: all `partial`; none claim equivalence or validation.
- Shared backend limitations: `schemas/splunk-cim.yml`, `schemas/sentinel-asim.yml`, `schemas/normalized-sql.yml`, `schemas/elastic-ecs.yml`, and `schemas/sigma.yml`.
- Tool-specific exceptions: server control-plane events require an authorized-server schema outside common endpoint models; other exceptions are recorded per rule.
- Required follow-up: map the declared schema for each backend, implement the canonical logic natively, compile, and test positive, negative, reordered, missing-event, and boundary-window fixtures before use.
