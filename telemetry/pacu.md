# Pacu telemetry requirements

Scope: the victim account's records of Pacu API calls at revision `7dd34aa0856b2a964763a70be9dc9d78abc08a81`. The tool runs on operator infrastructure.

## Consolidated collection plan

| Capability ID | Provider / product | Event types or IDs | Required fields | Enablement / configuration | Retention / correlation | Known gaps | Rules / procedures |
| --- | --- | --- | --- | --- | --- | --- | --- |
| PA-TEL-01 | AWS CloudTrail management events (write) | IAM policy, user, group, role and credential writes; Lambda, EventBridge, S3 notification, EC2, ECS, SSM, RDS, CloudTrail, GuardDuty, Config, CloudWatch, Cognito, Lightsail and API Gateway writes (event names in each rule) | eventName, eventSource, userIdentity ARN and userName, userAgent, sourceIPAddress, requestParameters, errorCode, invokedBy | Organization trail, all regions; management events logged by default | 30 to 60 minutes per principal; retain 90 days | Calls made after StopLogging are not recorded; IaC overlap (PA-DR-02) | All write-based rules; PA-P03 to PA-P07, PA-P09, PA-P10, PA-P12 to PA-P14 |
| PA-TEL-02 | AWS CloudTrail management events (read) | `List*`/`Describe*`/`Get*`, GetSecretValue, GetParameter(s), GenerateCredentialReport, GetCredentialReport, AssumeRole | as above | Management events set to All (read and write) | 30 minutes per principal | Write-only trails omit reads | `pacu_multi_service_enumeration_fanout`, `pacu_secret_value_bulk_retrieval`, `pacu_credential_report_generation`, `pacu_organization_member_role_assumption`, `pacu_access_denied_permission_bruteforce`; PA-P02, PA-P08, PA-P09, PA-P11, PA-P16 |
| PA-TEL-03 | AWS CloudTrail data events | S3 GetObject; EBS direct ListSnapshotBlocks and GetSnapshotBlock | bucket and key, snapshot ID, principal | Enable S3 and EBS direct data events on sensitive resources | 30 minutes per principal | Disabled by default; cost (PA-DR-01) | `pacu_s3_bulk_object_download`, `pacu_snapshot_and_database_takeover`; PA-P10, PA-P11 |
| PA-TEL-04 | Amazon EKS control-plane audit logs | Kubernetes audit `get`, `list` and `watch` on secrets; `create` on serviceaccounts/token | user, verb, resource, namespace | Enable EKS audit logging to CloudWatch and forward it | 30 minutes per user | Disabled by default (PA-DR-01) | `pacu_eks_service_account_token_collection`; PA-P15 |

## Rule-by-rule requirements

| YARA-L rule | Procedures | Capability IDs | Minimum viable telemetry | Optional enrichment | Failure mode if absent |
| --- | --- | --- | --- | --- | --- |
| `pacu_user_agent_session_suffix` | PA-P01 | PA-TEL-01, 02 | userAgent on any CloudTrail event | none | Suffix not set (PA-DR-03) |
| `pacu_iam_privilege_modification_burst` | PA-P03, P04 | PA-TEL-01 | IAM write event names and principal | deployment role list | IaC overlap (PA-DR-02) |
| `pacu_iam_credential_backdoor_other_user` | PA-P03, P04 | PA-TEL-01 | requestParameters.userName and userIdentity.userName | none | Missing userName fields disable the comparison |
| `pacu_eventbridge_lambda_backdoor_chain` | PA-P05 | PA-TEL-01 | CreateFunction and PutRule with eventPattern | deployment role list | eventPattern not normalized |
| `pacu_cfn_template_bucket_injection` | PA-P05 | PA-TEL-01 | PutBucketNotificationConfiguration with bucketName | none | Bucket name not normalized |
| `pacu_service_credential_issuance` | PA-P06 | PA-TEL-01, 02 | Lightsail and API Gateway event names with eventSource | none | eventSource not normalized |
| `pacu_security_group_open_ingress` | PA-P06 | PA-TEL-01 | AuthorizeSecurityGroupIngress with ipPermissions and groupId | none | ipPermissions not serialized |
| `pacu_ecs_task_definition_run` | PA-P09 | PA-TEL-01 | RegisterTaskDefinition and RunTask | pipeline role list | IaC overlap |
| `pacu_instance_userdata_modify_restart` | PA-P09 | PA-TEL-01 | ModifyInstanceAttribute (attribute) and StartInstances with instanceId | none | Attribute not normalized |
| `pacu_detection_service_impairment` | PA-P07 | PA-TEL-01 | Listed event names | change approvals | Dual-use updates (PA-DR-07) |
| `pacu_secret_value_bulk_retrieval` | PA-P08 | PA-TEL-02 | Secret and parameter reads with resource name | application role list | Write-only trail |
| `pacu_ssm_instance_profile_rce_chain` | PA-P09 | PA-TEL-01 | Profile association and SendCommand | onboarding role list | none |
| `pacu_snapshot_and_database_takeover` | PA-P10 | PA-TEL-01, 03 | RDS and EC2 snapshot events, requestParameter keys | DBA role list | EBS direct data events disabled |
| `pacu_s3_bulk_object_download` | PA-P11 | PA-TEL-03 | S3 GetObject data events | pipeline role list | Data events disabled (PA-DR-01) |
| `pacu_access_denied_permission_bruteforce` | PA-P02 | PA-TEL-01, 02 | errorCode on all events | none | Errors not normalized |
| `pacu_log_formula_injection` | PA-P13 | PA-TEL-01 | Trail and instance name values | none | Names not normalized |
| `pacu_organization_member_role_assumption` | PA-P09 | PA-TEL-02 | AssumeRole with role ARN and account | org admin list | Member-account trails not centralized |
| `pacu_multi_service_enumeration_fanout` | PA-P02, P11, P16 | PA-TEL-02 | Read events with eventSource | CSPM role list | Write-only trail |
| `pacu_sns_topic_subscription_fanout` | PA-P12 | PA-TEL-01 | Subscribe with topicArn | none | none |
| `pacu_credential_report_generation` | PA-P02 | PA-TEL-02 | Generate and Get credential report with userAgent | audit tool list | Write-only trail |
| `pacu_eks_service_account_token_collection` | PA-P15 | PA-TEL-04 | EKS audit verb, resource and namespace | none | Audit logging disabled |
| `pacu_cognito_pool_abuse` | PA-P14 | PA-TEL-01 | Cognito management event names | pipeline role list | IaC overlap |

## Deployment order

1. Write-event rules on default management events.
2. Enable read events on the trail for the enumeration and secret rules.
3. Enable S3 and EBS direct data events and EKS audit logging on sensitive resources.

## Validation checklist

- [x] Every current YARA-L rule appears in the rule matrix.
- [ ] requestParameters, errorCode and invokedBy placement was verified.
- [ ] Data-event and EKS audit coverage was inventoried.

## Unresolved telemetry gaps

- Data-event logging (PA-DR-01) is a tenant property. Compensating signals are named in `reviews/pacu/detection-review.md`.
