# Pacu public-rule comparison index

Pinned public revision: Elastic `9d792a8f6731542935156db61eaba88bf337e819`.

Five rules have meaningful public counterparts, each ending in a terminal decision.

No closer public candidate exists in the pinned snapshots for these rules, so they have no comparison:
- `pacu_access_denied_permission_bruteforce`
- `pacu_cfn_template_bucket_injection`
- `pacu_cognito_pool_abuse`
- `pacu_credential_report_generation`
- `pacu_ecs_task_definition_run`
- `pacu_eks_service_account_token_collection`
- `pacu_eventbridge_lambda_backdoor_chain`
- `pacu_iam_credential_backdoor_other_user`
- `pacu_iam_privilege_modification_burst`
- `pacu_log_formula_injection`
- `pacu_multi_service_enumeration_fanout`
- `pacu_organization_member_role_assumption`
- `pacu_s3_bulk_object_download`
- `pacu_security_group_open_ingress`
- `pacu_service_credential_issuance`
- `pacu_sns_topic_subscription_fanout`
- `pacu_user_agent_session_suffix`

| Internal rule | Procedures | Closest public candidate | Proposal | Decision |
| --- | --- | --- | --- | --- |
| [`pacu_detection_service_impairment`](./pacu_detection_service_impairment.md) | `PA-P07` | Elastic CloudTrail logging suspended; GuardDuty detector deletion; GuardDuty finding suppression | patch | reject |
| [`pacu_instance_userdata_modify_restart`](./pacu_instance_userdata_modify_restart.md) | `PA-P09` | Elastic EC2 stop/start with user data modification | patch | modify |
| [`pacu_secret_value_bulk_retrieval`](./pacu_secret_value_bulk_retrieval.md) | `PA-P08` | Elastic rapid Secrets Manager retrieval; SSM SecureString retrieval | patch | modify |
| [`pacu_ssm_instance_profile_rce_chain`](./pacu_ssm_instance_profile_rce_chain.md) | `PA-P09` | Elastic SSM SendCommand by rare user | new_rule | reject |
| [`pacu_snapshot_and_database_takeover`](./pacu_snapshot_and_database_takeover.md) | `PA-P10` | Elastic RDS snapshot export | patch | reject |
