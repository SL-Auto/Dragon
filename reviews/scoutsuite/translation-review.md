# ScoutSuite translation review

- Canonical rules: 7 YARA-L rules under `detections/scoutsuite/yaral/`.
- Secondary drafts reviewed: 35 files; 7 each in SPL, KQL, SQL, Elastic EQL and Sigma.
- Parity: complete by basename and `source_yaral` linkage.
- Shared backend limitations: `schemas/splunk-cim.yml`, `schemas/sentinel-asim.yml`, `schemas/normalized-sql.yml`, `schemas/elastic-ecs.yml` and `schemas/sigma.yml`.
- None of the drafts claims equivalence or validation.

## Exceptions

- **Native renders:** 6 rules (`scripts/native_translations/specs_scoutsuite.py`) are `high` in SPL, KQL, SQL and Sigma, and `partial` in EQL.
- **Downgraded to `partial` in every backend:** `scoutsuite_kubernetes_cluster_wide_secret_and_resource_list`. The drafts count distinct resource kinds but do not require that Secrets are among them.
- **Generator candidate retrieval (`partial`):** `scoutsuite_aws_userdata_and_credential_report_sweep`, an unordered two-event join with a per-leg instance count.
