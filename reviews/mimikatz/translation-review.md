# Mimikatz translation review

- Canonical rules: 19 YARA-L rules under `detections/mimikatz/yaral/`.
- Secondary drafts reviewed: 95 files; 19 each in SPL, KQL, SQL, Elastic EQL, and Sigma.
- Parity: complete by basename and source linkage.
- Fidelity: all `partial`; none claim equivalence or validation.
- Shared backend limitations: `schemas/splunk-cim.yml`, `schemas/sentinel-asim.yml`, `schemas/normalized-sql.yml`, `schemas/elastic-ecs.yml`, and `schemas/sigma.yml`.
- Tool-specific exceptions: offline procedures remain outside direct detection; other exceptions are recorded per rule in `fidelity` and `assumptions_and_gaps`.
- Required follow-up: map the declared schema for each backend, implement the canonical logic natively, compile, and test positive, negative, reordered, missing-event, and boundary-window fixtures before use.

## 2026-11-21 exceptions

- The generator drafts for `mimikatz_lsass_memory_access` were regenerated after the invalid `re.regex(...) nocase` form was replaced with inline `(?i)` (Rubeus REVIEW-010). They remain `partial`.
- `mimikatz_clipboard_device_access`, `mimikatz_directory_network_discovery` and `mimikatz_token_process_control` have no event-type predicate in canonical YARA-L. Their generator drafts therefore carry a wildcard event list and drop the description regex. They are candidate retrieval only and are recorded here as an open translation-quality item.
