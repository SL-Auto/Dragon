# Impacket translation review

- Canonical rules: 23 YARA-L rules under `detections/impacket/yaral/`.
- Secondary drafts reviewed: 115 files; 23 each in SPL, KQL, SQL, Elastic EQL, and Sigma.
- Parity: complete by basename and source linkage.
- Fidelity: generator drafts are `partial`; the three rules in the 2026-11-21 exceptions are `high` or `partial` as listed. None claim equivalence or validation.
- Shared backend limitations: `schemas/splunk-cim.yml`, `schemas/sentinel-asim.yml`, `schemas/normalized-sql.yml`, `schemas/elastic-ecs.yml`, and `schemas/sigma.yml`.
- Tool-specific exceptions: blocked-source constraints remain inherited from the canonical analysis; other exceptions are recorded per rule in `fidelity` and `assumptions_and_gaps`.
- Required follow-up: map the declared schema for each backend, implement the canonical logic natively, compile, and test positive, negative, reordered, missing-event, and boundary-window fixtures before use.

## 2026-11-21 exceptions — three rules and four anchored base rules

- Native translations for `impacket_ntlm_relay_with_privileged_effect`:
  - **KQL and SQL** (`high`): exact ordered joins on target host and acting user, with per-leg key aliasing.
  - **EQL** (`high`): native sequence.
  - **Sigma** (`high`): `temporal_ordered` with aliases.
  - **SPL** (`partial`): `stats` correlation compares the first and last leg times per key, which is weaker than per-pair ordering.
- `impacket_terminal_services_session_control_by_other_actor`:
  - **SPL, KQL and SQL** express the field-to-field inequality natively.
  - **Sigma** is `partial`: it cannot compare two fields.
  - **EQL** is `partial`: it cannot aggregate.
- `impacket_wmi_activity_operational_class_signal`: SPL, KQL, SQL and Sigma are `high`; EQL is `partial`.
- Four base rules received the anchoring fix (REVIEW-009) and were regenerated with `scripts/translate-yaral.ps1`, remaining `partial` drafts: `impacket_terminal_services_control`, `impacket_remote_registry_activity`, `impacket_wmi_subscription_change` and `impacket_rapid_scheduled_task_create_and_run`.
