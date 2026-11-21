# AdaptixC2 translation review

- Canonical rules: 10 YARA-L rules under `detections/adaptixc2/yaral/`.
- Secondary drafts reviewed: 50 files; 10 each in SPL, KQL, SQL, Elastic EQL and Sigma.
- Parity: complete by basename and `source_yaral` linkage.
- Shared backend limitations: `schemas/splunk-cim.yml`, `schemas/sentinel-asim.yml`, `schemas/normalized-sql.yml`, `schemas/elastic-ecs.yml` and `schemas/sigma.yml`.
- None of the drafts claims equivalence or validation.

## Exceptions

- **Native renders** (`scripts/native_translations/specs_adaptixc2.py`): `adaptix_raw_socket_dns_from_user_process`, `adaptix_recurrent_process_egress` and `adaptix_secondary_logon_hidden_interpreter`.
  - The two recurrence rules count events but not the distinct active-minute condition, so they are `partial` in every backend.
  - The seclogon rule is `high` in SPL, KQL, SQL and Sigma, and `partial` in EQL.
- **Generator candidate retrieval (`partial`):** the seven multi-event correlations. These are pipe-to-5145, listen-to-inbound, tunnel fan-out, egress-to-child, RWX, archive and screenshot with egress. Each needs a native per-backend join on host and process ID.
