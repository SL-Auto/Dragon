# Pacu translation review

- Canonical rules: 22 YARA-L rules under `detections/pacu/yaral/`.
- Secondary drafts reviewed: 110 files; 22 each in SPL, KQL, SQL, Elastic EQL and Sigma.
- Parity: complete by basename and `source_yaral` linkage.
- Shared backend limitations: `schemas/splunk-cim.yml`, `schemas/sentinel-asim.yml`, `schemas/normalized-sql.yml`, `schemas/elastic-ecs.yml` and `schemas/sigma.yml`.
- None of the drafts claims equivalence or validation.

## Exceptions

- **Native renders:** 21 rules are rendered by `scripts/native_translations/specs_pacu.py`.
  - Single-event rules are `high` in SPL, KQL, SQL and Sigma, and `partial` in EQL.
  - Ordered sequences (ECS register-then-run, user-data modify-then-start, profile association-then-SendCommand) are `high` in KQL, SQL, EQL and Sigma, and `partial` in SPL.
- **Downgraded to `partial` in every backend:**
  - `pacu_eventbridge_lambda_backdoor_chain` and `pacu_credential_report_generation`: the canonical rules are unordered, but the drafts impose first-leg-before-second-leg ordering.
  - `pacu_snapshot_and_database_takeover`: the drafts express only the two-step count, not the single password-reset branch.
- **Generator candidate retrieval (`partial`):** `pacu_iam_credential_backdoor_other_user`, because the target-user versus caller-user inequality needs a per-backend field comparison.
- **Column names:** normalized columns (`principal_arn`, `event_source`, `resource_name`, `request_attribute`, `ip_permissions`, `event_pattern`, `error_code`, `request_name`, `account_id`, `namespace`) need tenant mapping to CloudTrail and EKS audit fields.
