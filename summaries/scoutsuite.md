# ScoutSuite procedure summary

Generated context view. Use the coverage ledger and cited report as authoritative evidence.

- Tool ID: scoutsuite
- Revision: 7909f2fc6186063e5c9e7ddef8c4d7d1072c8f3d
- Lifecycle: analyzed
- Full evidence: reports/scoutsuite/source-analysis.md
- Coverage ledger: coverage/scoutsuite.yml

| Procedure | Summary | Telemetry | Detection | Canonical rules |
| --- | --- | --- | --- | --- |
| SS-P01 | AWS configuration audit | assessed | detected | scoutsuite_user_agent_in_cloud_audit, scoutsuite_aws_userdata_and_credential_report_sweep, scoutsuite_aws_multi_service_read_fanout |
| SS-P02 | Azure configuration audit | assessed | detected | scoutsuite_azure_arm_read_fanout, scoutsuite_user_agent_in_cloud_audit |
| SS-P03 | GCP configuration audit | assessed | detected | scoutsuite_user_agent_in_cloud_audit, scoutsuite_gcp_multi_service_read_fanout |
| SS-P04 | Kubernetes configuration audit | assessed | detected | scoutsuite_kubernetes_cluster_wide_secret_and_resource_list |
| SS-P05 | OCI Alibaba and DigitalOcean audits | assessed | detected | scoutsuite_user_agent_in_cloud_audit, scoutsuite_cli_execution |
| SS-P06 | execution on a monitored host | assessed | detected | scoutsuite_cli_execution |
