# ScoutSuite public-rule comparison index

Pinned public revision: Elastic `9d792a8f6731542935156db61eaba88bf337e819`. Microsoft Sentinel, Splunk and Chronicle snapshots contain no ScoutSuite-specific candidate.

One rule has a meaningful public counterpart.

No closer public candidate exists for these rules, so they have no comparison:
- `scoutsuite_aws_multi_service_read_fanout`
- `scoutsuite_aws_userdata_and_credential_report_sweep`
- `scoutsuite_azure_arm_read_fanout`
- `scoutsuite_gcp_multi_service_read_fanout`
- `scoutsuite_kubernetes_cluster_wide_secret_and_resource_list`
- `scoutsuite_user_agent_in_cloud_audit`

| Internal rule | Procedures | Closest public candidate | Proposal | Decision |
| --- | --- | --- | --- | --- |
| [`scoutsuite_cli_execution`](./scoutsuite_cli_execution.md) | `SS-P06` | Elastic cloud offensive framework execution | patch | reject |
