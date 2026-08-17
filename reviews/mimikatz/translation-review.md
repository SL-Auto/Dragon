# Mimikatz translation review

- Canonical rules: 17 YARA-L rules under `detections/mimikatz/yaral/`.
- Secondary drafts reviewed: 85 files; 17 each in SPL, KQL, SQL, Elastic EQL, and Sigma.
- Parity: complete by basename and source linkage.
- Fidelity: all `partial`; none claim equivalence or validation.
- Shared backend limitations: `schemas/splunk-cim.yml`, `schemas/sentinel-asim.yml`, `schemas/normalized-sql.yml`, `schemas/elastic-ecs.yml`, and `schemas/sigma.yml`.
- Tool-specific exceptions: offline procedures remain outside direct detection; other exceptions are recorded per rule in `fidelity` and `assumptions_and_gaps`.
- Required follow-up: map the declared schema for each backend, implement the canonical logic natively, compile, and test positive, negative, reordered, missing-event, and boundary-window fixtures before use.
