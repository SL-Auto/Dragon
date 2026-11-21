# Pacu procedure summary

Generated context view. Use the coverage ledger and cited report as authoritative evidence.

- Tool ID: pacu
- Revision: 7dd34aa0856b2a964763a70be9dc9d78abc08a81
- Lifecycle: analyzed
- Full evidence: reports/pacu/source-analysis.md
- Coverage ledger: coverage/pacu.yml

| Procedure | Summary | Telemetry | Detection | Canonical rules |
| --- | --- | --- | --- | --- |
| PA-P01 | session identity and user agent | assessed | detected | pacu_user_agent_session_suffix |
| PA-P02 | IAM and permission enumeration | assessed | detected | pacu_access_denied_permission_bruteforce, pacu_credential_report_generation, pacu_multi_service_enumeration_fanout |
| PA-P03 | IAM privilege escalation | assessed | detected | pacu_iam_privilege_modification_burst, pacu_iam_credential_backdoor_other_user |
| PA-P04 | IAM credential and trust backdoors | assessed | detected | pacu_iam_credential_backdoor_other_user, pacu_iam_privilege_modification_burst |
| PA-P05 | event-driven Lambda and template backdoors | assessed | detected | pacu_eventbridge_lambda_backdoor_chain, pacu_cfn_template_bucket_injection |
| PA-P06 | network and service access backdoors | assessed | detected | pacu_security_group_open_ingress, pacu_service_credential_issuance |
| PA-P07 | detection and logging impairment | assessed | detected | pacu_detection_service_impairment |
| PA-P08 | secret and credential retrieval | assessed | detected | pacu_secret_value_bulk_retrieval, pacu_multi_service_enumeration_fanout |
| PA-P09 | remote execution and lateral movement | assessed | detected | pacu_ssm_instance_profile_rce_chain, pacu_ecs_task_definition_run, pacu_instance_userdata_modify_restart, pacu_organization_member_role_assumption |
| PA-P10 | snapshot and database takeover | assessed | detected | pacu_snapshot_and_database_takeover |
| PA-P11 | bulk data download | assessed | detected | pacu_s3_bulk_object_download, pacu_multi_service_enumeration_fanout |
| PA-P12 | SNS topic subscription | assessed | detected | pacu_sns_topic_subscription_fanout |
| PA-P13 | CloudTrail log formula injection | assessed | detected | pacu_log_formula_injection |
| PA-P14 | Cognito abuse | assessed | detected | pacu_cognito_pool_abuse |
| PA-P15 | EKS service-account token collection | assessed | detected | pacu_eks_service_account_token_collection |
| PA-P16 | multi-service enumeration | assessed | detected | pacu_multi_service_enumeration_fanout |
