# Sliver translation review

- Canonical rules: 21 YARA-L rules under `detections/sliver/yaral/`.
- Secondary drafts reviewed: 105 files; 21 each in SPL, KQL, SQL, Elastic EQL, and Sigma.
- Parity: complete by basename and source linkage.
- Fidelity: all `partial`; none claim equivalence or validation.
- Shared backend limitations: `schemas/splunk-cim.yml`, `schemas/sentinel-asim.yml`, `schemas/normalized-sql.yml`, `schemas/elastic-ecs.yml`, and `schemas/sigma.yml`.
- Tool-specific exceptions: server control-plane events require an authorized-server schema outside common endpoint models; other exceptions are recorded per rule.
- Required follow-up: map the declared schema for each backend, implement the canonical logic natively, compile, and test positive, negative, reordered, missing-event, and boundary-window fixtures before use.

## 2026-11-21 exceptions — comparison-record reconciliation

- The generator drafts for `sliver_remote_admin_sequence`, `sliver_explicit_credential_service_creation` and `sliver_lsass_access_from_network_process` were regenerated after REVIEW-015 and REVIEW-016.
- `sliver_remote_admin_sequence` had emitted a wildcard event list after anchoring until the generator was fixed. It now lists 4624, 4697, `sshd_auth_success` and `sshd_command`. The session-ID join remains unexpressed in these `partial` drafts.
