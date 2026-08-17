# Impacket translation review

- Canonical rules: 20 YARA-L rules under `detections/impacket/yaral/`.
- Secondary drafts reviewed: 100 files; 20 each in SPL, KQL, SQL, Elastic EQL, and Sigma.
- Parity: complete by basename and source linkage.
- Fidelity: all `partial`; none claim equivalence or validation.
- Shared backend limitations: `schemas/splunk-cim.yml`, `schemas/sentinel-asim.yml`, `schemas/normalized-sql.yml`, `schemas/elastic-ecs.yml`, and `schemas/sigma.yml`.
- Tool-specific exceptions: blocked-source constraints remain inherited from the canonical analysis; other exceptions are recorded per rule in `fidelity` and `assumptions_and_gaps`.
- Required follow-up: map the declared schema for each backend, implement the canonical logic natively, compile, and test positive, negative, reordered, missing-event, and boundary-window fixtures before use.
