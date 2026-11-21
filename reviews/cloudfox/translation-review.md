# CloudFox translation review

- Canonical rules: 15 YARA-L rules under `detections/cloudfox/yaral/`.
- Secondary drafts reviewed: 75 files; 15 each in SPL, KQL, SQL, Elastic EQL and Sigma.
- Parity: complete by basename and `source_yaral` linkage.
- Shared backend limitations: `schemas/splunk-cim.yml`, `schemas/sentinel-asim.yml`, `schemas/normalized-sql.yml`, `schemas/elastic-ecs.yml` and `schemas/sigma.yml`.
- None of the drafts claims equivalence or validation.

## Exceptions

- **Native renders:** all 15 rules are single-event aggregations, rendered by `scripts/native_translations/specs_cloudfox.py`.
  - SPL, KQL, SQL and Sigma are `high`; EQL is `partial`, because it cannot aggregate.
- **Normalized column names** (`principal_arn`, `event_source`, `request_attribute`, `lookup_attributes`, `caller`, `requester`, `principal_email`, `service_name`, `resource_provider`, `query`) stand for the CloudTrail, Azure Activity, StorageBlobLogs and Cloud Audit fields named in each rule's prerequisites. They render as `labels.*` in ECS and require tenant mapping, for example `aws.cloudtrail.*` or `gcp.audit.*` in Elastic, or `AWSCloudTrail` and `AzureActivity` columns in Sentinel.
- **Sigma** uses generic `cloudtrail`, `azure_activity`, `azure_storage` and `gcp_audit` log-source categories, which need backend pipeline mapping.
