# Cobalt Strike Beacon translation review

- Canonical rules: 21 YARA-L rules under `detections/cobalt-strike-beacon/yaral/`.
- Secondary drafts reviewed: 105 files; 21 each in SPL, KQL, SQL, Elastic EQL, and Sigma.
- Parity: complete by basename and source linkage.
- Fidelity: all `partial`; none claim equivalence or validation.
- Shared backend limitations: `schemas/splunk-cim.yml`, `schemas/sentinel-asim.yml`, `schemas/normalized-sql.yml`, `schemas/elastic-ecs.yml`, and `schemas/sigma.yml`.
- Tool-specific exceptions: none beyond the per-rule `fidelity` and `assumptions_and_gaps` metadata.
- Required follow-up: map the declared schema for each backend, implement the canonical logic natively, compile, and test positive, negative, reordered, missing-event, and boundary-window fixtures before use.
