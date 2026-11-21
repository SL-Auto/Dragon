---
title: Pacu comprehensive source analysis
domain: tool-analysis
type: evidence
authority: reference
---

# Pacu comprehensive source analysis

## Scope and safety

- **Revision:** static analysis of official revision `7dd34aa0856b2a964763a70be9dc9d78abc08a81` (committed 2026-11-19) from <https://github.com/RhinoSecurityLabs/pacu>, accessed 2026-11-21.
- **Handling:** shallow source clone to `sources/pacu-src/` (gitignored), not built or run. Two bundled Lambda payload archives (`iam__privesc_scan/lambda.zip`, `PassExistingRoleToNewCodeStarProject/empty.zip`) were deleted unopened, because archives are a forbidden sample type. The analysis uses module source only.
- **Eligibility:** Pacu runs on operator infrastructure with stolen or assigned AWS credentials. Its API calls are recorded in the victim account's CloudTrail, and some (EKS, S3 data events, Cognito) in service logs. Those victim-side records are the analyzed surface.
- **Excluded as operator-local or attacker-account-only:**
  - The interactive shell, session database and module loader (`pacu/main.py`, `pacu/core`); their only victim-visible effect is the user-agent handling recorded in PA-P01.
  - `iam__decode_accesskey_id`: offline decoding, no API call.
  - `ebs__enum_snapshots_unauth`: public-snapshot discovery from the attacker's own account.
  - The principal-existence probing in `iam__enum_roles` and `iam__enum_users`: trust-policy updates in the attacker's own account, invisible to the victim. Their follow-on `AssumeRole` attempts into the victim are in scope (PA-P09).

## Completeness inventory

All 77 modules under `pacu/modules/` were mapped to their boto3 and Kubernetes API calls (extracted from each `main.py` and helpers). Module families and their procedures:

| Procedure | Modules |
| --- | --- |
| PA-P01 | all modules (session credentials, `sts:GetCallerIdentity`, user-agent suffix and OS user-agent replacement, `main.py` L1594-1601, L1668-1671, L876-881) |
| PA-P02 | `iam__enum_users_roles_policies_groups`, `iam__enum_permissions`, `iam__enum_action_query`, `iam__bruteforce_permissions`, `iam__get_credential_report`, `iam__detect_honeytokens` |
| PA-P03 | `iam__privesc_scan` (policy attachment, inline policies, policy versions, group membership, role passing to Lambda, Glue, CloudFormation, CodeStar and EC2, access keys and login profiles) |
| PA-P04 | `iam__backdoor_users_keys`, `iam__backdoor_users_password`, `iam__backdoor_assume_role` |
| PA-P05 | `lambda__backdoor_new_users`, `lambda__backdoor_new_roles`, `lambda__backdoor_new_sec_groups` (EventBridge rules on IAM CreateUser/CreateRole and EC2 CreateSecurityGroup with Lambda targets), `cfn__resource_injection` (S3 notifications on CloudFormation template buckets) |
| PA-P06 | `ec2__backdoor_ec2_sec_groups`, `lightsail__generate_ssh_keys`, `lightsail__generate_temp_access`, `api_gateway__create_api_keys` |
| PA-P07 | `detection__disruption` (CloudTrail StopLogging/DeleteTrail/UpdateTrail, GuardDuty DeleteDetector/UpdateDetector, Config Delete/StopConfigurationRecorder and DeleteConfigRule, DeleteFlowLogs, CloudWatch DeleteAlarms/DisableAlarmActions), `guardduty__whitelist_ip` (CreateIPSet/UpdateIPSet) |
| PA-P08 | `secrets__enum` (GetSecretValue, GetParameter), `systemsmanager__download_parameters` (GetParameters), `ec2__download_userdata` (DescribeInstanceAttribute userData, DescribeLaunchTemplateVersions), `codebuild__enum` (BatchGetProjects and builds) |
| PA-P09 | `systemsmanager__rce_ec2` (role, instance profile, AssociateIamInstanceProfile, SendCommand), `ecs__backdoor_task_def` (RegisterTaskDefinition, RunTask), `ec2__startup_shell_script` (ModifyInstanceAttribute userData with stop and start), `organizations__assume_role`, `iam__enum_roles` (AssumeRole attempts) |
| PA-P10 | `rds__explore_snapshots` (CreateDBSnapshot, RestoreDBInstanceFromDBSnapshot, ModifyDBInstance MasterUserPassword), `ebs__explore_snapshots` (CreateSnapshot, CreateVolume, AttachVolume), `ebs__download_snapshots` (EBS direct APIs) |
| PA-P11 | `s3__download_bucket` (ListObjects, GetObject), `cloudwatch__download_logs`, `cloudtrail__download_event_history` (LookupEvents), `cloudformation__download_data`, `inspector__get_reports` |
| PA-P12 | `sns__subscribe` (Subscribe attacker endpoints) |
| PA-P13 | `cloudtrail__csv_injection` (CreateTrail and RunInstances values beginning with spreadsheet formula characters) |
| PA-P14 | `cognito__attack` (user pool and identity pool creation, AdminCreateUser, attribute updates, InitiateAuth) |
| PA-P15 | `eks__collect_tokens` (DescribeCluster, then Kubernetes API pod listing and service-account token reads) |
| PA-P16 | all `*__enum` and listing modules (acm, apigateway, codebuild, cognito, detection services, ds, dynamodb, ebs, ec2, ecr, ecs, eks, elasticbeanstalk, elb, glue, guardduty accounts, lambda, lightsail, mq, organizations, rds, route53, sns, transfer_family, vpc lateral movement, waf) |

## Procedure analysis

| ID | Procedure | Ordered behavior and interfaces | Security effect | Victim-side telemetry and gaps | ATT&CK | Confidence |
| --- | --- | --- | --- | --- | --- | --- |
| PA-P01 | Session identity and user agent | `sts:GetCallerIdentity`. An optional `set_ua_suffix` appends `Pacu-Session-<uuid>` (or an operator string) as boto3 `user_agent_extra`. On Kali, Parrot or Pentoo hosts the OS-identifying user agent is replaced | Establishes identity; affects attribution in logs | CloudTrail `userAgent` carries the suffix when set; OS-identifying user agents are absent | T1078.004 | High |
| PA-P02 | IAM and permission enumeration | Lists users, roles, groups and policies; brute-forces permissions by calling many APIs and recording AccessDenied; generates and reads the credential report; triggers errors to read the caller ARN (honeytoken check) | Permission map and credential-hygiene data | CloudTrail; bursts of AccessDenied across many event names; `GenerateCredentialReport`/`GetCredentialReport` | T1087.004, T1069.003, T1580 | High |
| PA-P03 | IAM privilege escalation | Attach managed policies; put inline policies; create policy versions as default; add a user to a group; update trust policies; pass roles to new Lambda, Glue, CloudFormation, CodeStar or EC2 resources; create keys or login profiles | Escalates privileges | CloudTrail IAM write events (management events, logged by default) | T1098.003, T1548, T1078.004 | High |
| PA-P04 | IAM credential and trust backdoors | `CreateAccessKey` and `CreateLoginProfile`/`UpdateLoginProfile` for other users; `UpdateAssumeRolePolicy` adding an attacker principal | Persistent access | CloudTrail; `requestParameters.userName` differs from the caller | T1098.001, T1098.003 | High |
| PA-P05 | Event-driven Lambda and template backdoors | Creates a Lambda function plus an EventBridge rule on CreateUser, CreateRole or CreateSecurityGroup, with targets and invoke permission; or injects S3 notifications on CloudFormation template buckets with a Lambda function | Automatic backdooring of new resources | CloudTrail `CreateFunction`, `PutRule`, `PutTargets`, `AddPermission`, `PutBucketNotificationConfiguration` | T1546, T1098 | High |
| PA-P06 | Network and service access backdoors | Opens security-group ingress; creates or imports Lightsail key pairs; retrieves Lightsail temporary SSH access; creates API Gateway keys | Remote access paths | CloudTrail `AuthorizeSecurityGroupIngress`, Lightsail `CreateKeyPair`/`ImportKeyPair`/`GetInstanceAccessDetails`, `CreateApiKey` | T1098, T1133 | High |
| PA-P07 | Detection and logging impairment | Stops or deletes trails, deletes or disables GuardDuty detectors, stops or deletes Config recorders and rules, deletes flow logs and alarms, or adds GuardDuty trusted IP sets | Blinds monitoring | CloudTrail management events, logged even when they impair logging (except events after logging stops) | T1562.008, T1562.001 | High |
| PA-P08 | Secret and credential retrieval | `GetSecretValue`, `GetParameter(s)` with decryption, instance and launch-template user data, CodeBuild project environments | Credential access | CloudTrail management read events | T1552.001, T1552.005, T1555.006 | High |
| PA-P09 | Remote execution and lateral movement | Creates a role and instance profile and attaches it to instances, then SSM `SendCommand`; registers and runs ECS task definitions; replaces instance user data and restarts the instance; assumes OrganizationAccountAccessRole into member accounts | Code execution on instances and in accounts | CloudTrail sequences on the same principal; SSM command history | T1651, T1609, T1059, T1078.004 | High |
| PA-P10 | Snapshot and database takeover | Snapshots or restores RDS instances and resets master passwords; creates volumes from EBS snapshots and attaches them; reads snapshot blocks through EBS direct APIs | Data access to databases and disks | CloudTrail RDS and EC2 events; EBS direct API data events (must be enabled) | T1578, T1530 | High |
| PA-P11 | Bulk data download | Lists and downloads S3 objects; downloads CloudWatch logs, CloudTrail history, CloudFormation templates and Inspector reports | Data collection | S3 data events (must be enabled); CloudTrail read events | T1530, T1119 | High |
| PA-P12 | SNS topic subscription | Subscribes operator email or HTTP endpoints to topics | Ongoing data interception | CloudTrail `Subscribe` | T1530 | High |
| PA-P13 | CloudTrail log injection | Creates trails or launches instances whose names begin with formula characters, to inject spreadsheet formulas into exported logs | Analyst-tool exploitation | CloudTrail request parameters | T1059 (analyst tooling) | Medium |
| PA-P14 | Cognito abuse | Creates pools and clients, creates users, updates attributes and authenticates to obtain identity-pool credentials | Unauthorized identities | CloudTrail Cognito management events; user-pool data-plane events vary | T1136, T1098 | Medium |
| PA-P15 | EKS service-account token collection | `DescribeCluster`, then Kubernetes API pod listing and service-account token reads with the caller's mapped identity | Kubernetes credential access | EKS audit logs (control-plane logging must be enabled) | T1528, T1552.007 | High |
| PA-P16 | Multi-service enumeration | Read-only listing across about 30 services | Attack-surface map | CloudTrail read events; breadth across event sources | T1580, T1526 | High |

## Observed facts versus inference

- **Observed:** every API call named above, the user-agent suffix mechanism and the EventBridge event patterns of the Lambda backdoors.
- **Inference:** detection thresholds and the equivalence groupings used for rules.
