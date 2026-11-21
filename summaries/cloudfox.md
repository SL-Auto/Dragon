# CloudFox procedure summary

Generated context view. Use the coverage ledger and cited report as authoritative evidence.

- Tool ID: cloudfox
- Revision: f65be085cde3768281c2dbafc57542a56ee12ebe
- Lifecycle: analyzed
- Full evidence: reports/cloudfox/source-analysis.md
- Coverage ledger: coverage/cloudfox.yml

| Procedure | Summary | Telemetry | Detection | Canonical rules |
| --- | --- | --- | --- | --- |
| CF-A01 | AWS identity and organization context | assessed | detected | cloudfox_aws_multi_service_enumeration_fanout |
| CF-A02 | AWS IAM and trust enumeration | assessed | detected | cloudfox_aws_multi_service_enumeration_fanout, cloudfox_aws_authorization_details_dump |
| CF-A03 | AWS policy simulation | assessed | detected | cloudfox_aws_policy_simulation_fanout |
| CF-A04 | AWS multi-service inventory | assessed | detected | cloudfox_aws_multi_service_enumeration_fanout |
| CF-A05 | AWS secret-bearing configuration reads | assessed | detected | cloudfox_aws_instance_userdata_bulk_read, cloudfox_aws_secret_bearing_config_sweep |
| CF-A06 | AWS secret inventory metadata | assessed | detected | cloudfox_aws_multi_service_enumeration_fanout |
| CF-A07 | AWS CloudTrail AssumeRole history lookup | assessed | detected | cloudfox_aws_programmatic_assumerole_history_lookup |
| CF-Z01 | Azure tenant and subscription context | assessed | detected | cloudfox_azure_arm_read_fanout |
| CF-Z02 | Azure RBAC and directory users | assessed | detected | cloudfox_azure_arm_read_fanout |
| CF-Z03 | Azure resource inventory | assessed | detected | cloudfox_azure_arm_read_fanout |
| CF-Z04 | Azure secret-bearing reads | assessed | detected | cloudfox_azure_app_settings_secret_list, cloudfox_azure_arm_read_fanout |
| CF-Z05 | Azure storage container and blob listing | assessed | detected | cloudfox_azure_storage_listing_fanout |
| CF-G01 | GCP IAM and identity enumeration | assessed | detected | cloudfox_gcp_iam_policy_read_fanout |
| CF-G02 | GCP multi-service inventory | assessed | detected | cloudfox_gcp_multi_service_inventory |
| CF-G03 | GCP BigQuery data sampling | assessed | detected | cloudfox_gcp_bigquery_select_star_sampling |
| CF-G04 | GCP log-entry scanning | assessed | detected | cloudfox_gcp_content_listing_fanout |
| CF-G05 | GCP bucket object listing | assessed | detected | cloudfox_gcp_content_listing_fanout |
| CF-G06 | GCP secret inventory metadata | assessed | detected | cloudfox_gcp_multi_service_inventory, cloudfox_gcp_secret_metadata_multi_project |
| CF-X01 | CloudFox execution on a monitored endpoint | assessed | detected | cloudfox_cli_module_grammar_execution |
