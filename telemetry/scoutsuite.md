# ScoutSuite telemetry requirements

Scope: victim cloud audit records of ScoutSuite reads, and host launch, at revision `7909f2fc6186063e5c9e7ddef8c4d7d1072c8f3d`.

## Consolidated collection plan

| Capability ID | Provider / product | Event types or IDs | Required fields | Enablement / configuration | Retention / correlation | Known gaps | Rules / procedures |
| --- | --- | --- | --- | --- | --- | --- | --- |
| SS-TEL-01 | AWS CloudTrail | Read management events; `DescribeInstanceAttribute`, `GenerateCredentialReport`, `GetCredentialReport` | eventName, eventSource, userIdentity ARN, userAgent, requestParameters | Trail with management events set to All | 30 to 60 minutes per principal | Write-only trails omit reads | AWS rules and the user-agent rule; SS-P01 |
| SS-TEL-02 | Google Cloud Audit Logs | Data Access entries (list, get, search, getIamPolicy) | methodName, serviceName, principalEmail, `callerSuppliedUserAgent` | Enable Data Access logs broadly | 30 minutes per principal | Disabled by default | GCP breadth and user-agent rules; SS-P03 |
| SS-TEL-03 | Azure ARM read plane | `AZURE_RESOURCE_READ` (normalized) | caller, resource provider | Requires read-plane telemetry | 30 minutes per caller | Not in the default Activity Log (SS-DR-01) | `scoutsuite_azure_arm_read_fanout`; SS-P02 |
| SS-TEL-04 | Kubernetes API audit | `list` on secrets and other kinds | user, verb, resource, namespace | EKS, AKS or GKE control-plane audit logging | 10 minutes per user | Disabled by default | Kubernetes rule; SS-P04 |
| SS-TEL-05 | OCI Audit and Alibaba ActionTrail | Read API events | caller, user agent | Default audit logging, forwarded | 1 hour per caller | Field mapping varies | user-agent rule; SS-P05 |
| SS-TEL-06 | Process creation | Sysmon Event ID 1, Security 4688, auditd EXECVE, EDR `PROCESS_LAUNCH` | command line, image, host | Command-line capture | 1 hour per host | Only when run on a monitored host | `scoutsuite_cli_execution`; SS-P05, SS-P06 |

## Rule-by-rule requirements

| YARA-L rule | Procedures | Capability IDs | Minimum viable telemetry | Optional enrichment | Failure mode if absent |
| --- | --- | --- | --- | --- | --- |
| `scoutsuite_user_agent_in_cloud_audit` | SS-P01, P02, P03, P05 | SS-TEL-01, 02, 05 | User agent on audit events | none | Azure reads unrecorded (SS-DR-01); modified build (SS-DR-02) |
| `scoutsuite_aws_userdata_and_credential_report_sweep` | SS-P01 | SS-TEL-01 | userData reads and credential-report events | auditor role list | Write-only trail |
| `scoutsuite_aws_multi_service_read_fanout` | SS-P01 | SS-TEL-01 | Read events with eventSource | CSPM role list | Write-only trail |
| `scoutsuite_gcp_multi_service_read_fanout` | SS-P03 | SS-TEL-02 | Data Access entries with serviceName | SCC and CSPM accounts | Data Access disabled |
| `scoutsuite_azure_arm_read_fanout` | SS-P02 | SS-TEL-03 | Read-plane telemetry | posture identities | No read-plane source |
| `scoutsuite_kubernetes_cluster_wide_secret_and_resource_list` | SS-P04 | SS-TEL-04 | Audit entries with verb and resource | controller allowlist | Audit logging disabled |
| `scoutsuite_cli_execution` | SS-P05, P06 | SS-TEL-06 | Process command line | none | Tool run on operator infrastructure |

## Deployment order

1. The user-agent rule on CloudTrail and Cloud Audit.
2. The secret-read rules (AWS and Kubernetes).
3. Breadth rules with CSPM allowlists.

## Validation checklist

- [x] Every current YARA-L rule appears in the rule matrix.
- [ ] User-agent field placement was verified per provider.

## Unresolved telemetry gaps

- Azure read and DigitalOcean read visibility (SS-DR-01) are provider properties.
