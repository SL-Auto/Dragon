# CloudFox public-rule comparison index

Pinned public revision: Elastic `9d792a8f6731542935156db61eaba88bf337e819`. Microsoft Sentinel `c3361d9ff34320e7fe3314d5f9063e15470ca53e` and Splunk `21509485465aaed2cfa4604e3d2ab5ee52975f0a` were searched with no closer CloudFox-relevant candidates.

Five rules have meaningful public counterparts and are compared below, each ending in a terminal decision. Two adopted proposals were implemented independently as `cloudfox_gcp_secret_metadata_multi_project` and `cloudfox_cli_module_grammar_execution`.

No meaningful public candidate exists in the pinned snapshots for these rules, so they have no comparison:
- `cloudfox_aws_secret_bearing_config_sweep`
- `cloudfox_aws_policy_simulation_fanout`
- `cloudfox_aws_programmatic_assumerole_history_lookup`
- `cloudfox_azure_arm_read_fanout`
- `cloudfox_azure_storage_listing_fanout`
- `cloudfox_gcp_bigquery_select_star_sampling`
- `cloudfox_gcp_iam_policy_read_fanout`
- `cloudfox_gcp_content_listing_fanout`

| Internal rule | Procedures | Closest public candidate | Proposal | Decision |
| --- | --- | --- | --- | --- |
| [`cloudfox_aws_multi_service_enumeration_fanout`](./cloudfox_aws_multi_service_enumeration_fanout.md) | `CF-A01,CF-A02,CF-A04,CF-A06` | Elastic multiple discovery API calls via CLI | patch | modify |
| [`cloudfox_aws_instance_userdata_bulk_read`](./cloudfox_aws_instance_userdata_bulk_read.md) | `CF-A05` | Elastic bulk EC2 user data enumeration; EC2 user data request (new terms) | patch | modify |
| [`cloudfox_gcp_multi_service_inventory`](./cloudfox_gcp_multi_service_inventory.md) | `CF-G02,CF-G06` | Elastic GCP Secret Manager ListSecrets across projects | new_rule | modify |
| [`cloudfox_azure_app_settings_secret_list`](./cloudfox_azure_app_settings_secret_list.md) | `CF-Z04` | Elastic Azure storage account keys accessed | patch | reject |
| [`cloudfox_aws_authorization_details_dump`](./cloudfox_aws_authorization_details_dump.md) | `CF-A02` | Elastic cloud offensive framework execution | new_rule | modify |
