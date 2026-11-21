# CloudFox telemetry requirements

Scope: the victim-side audit records produced by CloudFox's API calls at revision `f65be085cde3768281c2dbafc57542a56ee12ebe`. The tool runs on the operator machine, so there is no host telemetry.

## Consolidated collection plan

| Capability ID | Provider / product | Event types or IDs | Required fields | Enablement / configuration | Retention / correlation | Known gaps | Rules / procedures |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CF-TEL-01 | AWS CloudTrail | Management events: read-only `List*`/`Describe*`/`Get*`; `DescribeInstanceAttribute`, `DescribeTaskDefinition`, `BatchGetProjects`, `GetTemplate`, `ListFunctions`, `GetFunctionConfiguration`, `SimulatePrincipalPolicy`, `GetAccountAuthorizationDetails`, `LookupEvents` | eventName, eventSource, userIdentity ARN, sourceIPAddress, userAgent, requestParameters (attribute, policySourceArn, lookupAttributes), resource ID | Organization or multi-region trail with management events set to **All** (read and write); centralize every account | 30 minutes per principal; retain 90 days | Read events excluded on write-only trails; assumed-role session names split identities | All six AWS rules; CF-A01 to CF-A07 |
| CF-TEL-02 | Azure Activity Log | `Microsoft.Web/sites/config/list/action` (and slots) | operationName, caller, resourceId, callerIpAddress | Export the Activity Log (Administrative category) to the SIEM | 30 minutes per caller | No user agent; the portal Configuration blade issues the same action | `cloudfox_azure_app_settings_secret_list`; CF-Z04 |
| CF-TEL-03 | Azure Resource Manager read plane | `AZURE_RESOURCE_READ` (normalized) | caller, resource provider, resource ID | Requires read-plane telemetry (for example a gateway, Defender for Resource Manager or an equivalent product); the default Activity Log omits reads | 30 minutes per caller | Often unavailable | `cloudfox_azure_arm_read_fanout`; CF-Z01 to CF-Z04 |
| CF-TEL-04 | Azure Storage | `StorageBlobLogs` `ListContainers`, `ListBlobs` | OperationName, RequesterObjectId or UPN, AccountName, CallerIpAddress | Diagnostic settings on every storage account (blob read logs) | 30 minutes per requester | Not enabled by default; SAS and key access lack an object ID | `cloudfox_azure_storage_listing_fanout`; CF-Z05 |
| CF-TEL-05 | Microsoft Entra / Graph | `MicrosoftGraphActivityLogs` (users reads) | appId, user or service principal, request URI | Diagnostic setting for Graph activity logs | Context only | No current CloudFox rule depends on it; the Azure ARM read rule is the breadth signal | Context for CF-Z02 |
| CF-TEL-06 | Google Cloud Audit Logs | BigQuery `jobservice.insert` / `google.cloud.bigquery.v2.JobService.InsertJob` (DATA_READ, on by default) | methodName, principalEmail, resourceName, job query text | Default for BigQuery; ensure the query field is not redacted in the pipeline | 30 minutes per principal | Redacted query text | `cloudfox_gcp_bigquery_select_star_sampling`; CF-G03 |
| CF-TEL-07 | Google Cloud Audit Logs | `getIamPolicy` methods (ADMIN_READ) | methodName, serviceName, resourceName, principalEmail | Enable ADMIN_READ Data Access logs for Resource Manager, IAM and key services | 30 minutes per principal | Disabled by default | `cloudfox_gcp_iam_policy_read_fanout`; CF-G01 |
| CF-TEL-08 | Google Cloud Audit Logs | `storage.objects.list`, `google.logging.v2.LoggingServiceV2.ListLogEntries` (DATA_READ) | methodName, resourceName, principalEmail | Enable DATA_READ Data Access logs for Cloud Storage and Cloud Logging | 30 minutes per principal | Disabled by default; high volume | `cloudfox_gcp_content_listing_fanout`; CF-G04, CF-G05 |
| CF-TEL-10 | Google Cloud Audit Logs | `google.cloud.secretmanager.v1.SecretManagerService.ListSecrets` (DATA_READ) | methodName, principalEmail, project ID | Enable Data Access logs for Secret Manager | 30 minutes per principal | Disabled by default | `cloudfox_gcp_secret_metadata_multi_project`; CF-G06 |
| CF-TEL-11 | Endpoint process creation (only when CloudFox runs on a monitored host) | Sysmon Event ID 1, Security 4688 with command line, Linux auditd EXECVE or EDR `PROCESS_LAUNCH` | command line, image path, user, host | Enable command-line capture | 1 hour per host and image | Not visible when the tool runs on operator infrastructure | `cloudfox_cli_module_grammar_execution`; CF-X01 |
| CF-TEL-09 | Google Cloud Audit Logs | List, Get, Search and Aggregated methods across services | methodName, serviceName, principalEmail | Enable Data Access logs broadly (coverage scales with enablement) | 30 minutes per principal | Partial enablement undercounts breadth | `cloudfox_gcp_multi_service_inventory`; CF-G02, CF-G06 |

## Rule-by-rule requirements

| YARA-L rule | Procedures | Capability IDs | Minimum viable telemetry | Optional enrichment | Failure mode if absent |
| --- | --- | --- | --- | --- | --- |
| `cloudfox_aws_multi_service_enumeration_fanout` | CF-A01, A02, A04, A06 | CF-TEL-01 | CloudTrail read management events with eventSource and principal ARN | approved CSPM role list | Write-only trails hide all reads (CF-DR-01) |
| `cloudfox_aws_instance_userdata_bulk_read` | CF-A05 | CF-TEL-01 | `DescribeInstanceAttribute` with `requestParameters.attribute` and instance ID | provisioning role list | Missing attribute mapping cannot separate user data from other attributes |
| `cloudfox_aws_secret_bearing_config_sweep` | CF-A05 | CF-TEL-01 | Listed event names with principal and userAgent | pipeline role list | Without userAgent, console browsing inflates counts (CF-DR-02) |
| `cloudfox_aws_policy_simulation_fanout` | CF-A03 | CF-TEL-01 | `SimulatePrincipalPolicy` with `policySourceArn` | governance role list | Without policySourceArn, distinct principals cannot be counted |
| `cloudfox_aws_authorization_details_dump` | CF-A02 | CF-TEL-01 | `GetAccountAuthorizationDetails` with principal | governance role list | Write-only trails hide it |
| `cloudfox_aws_programmatic_assumerole_history_lookup` | CF-A07 | CF-TEL-01 | `LookupEvents` with lookupAttributes and userAgent | analyst/SOAR role list | Without lookupAttributes the AssumeRole filter is invisible |
| `cloudfox_azure_app_settings_secret_list` | CF-Z04 | CF-TEL-02 | Activity Log list action with caller and resourceId | deployment identity list | Activity Log not exported |
| `cloudfox_azure_arm_read_fanout` | CF-Z01 to Z04 | CF-TEL-03 | Normalized ARM reads with caller and resource provider | posture-tool identities | Default telemetry omits reads (CF-DR-01) |
| `cloudfox_azure_storage_listing_fanout` | CF-Z05 | CF-TEL-04 | StorageBlobLogs list operations with requester and account | backup and catalog identities | Diagnostic settings absent |
| `cloudfox_gcp_bigquery_select_star_sampling` | CF-G03 | CF-TEL-06 | BigQuery insert-job audit with query text | profiler service accounts | Redacted query text (CF-DR-07) |
| `cloudfox_gcp_iam_policy_read_fanout` | CF-G01 | CF-TEL-07 | `getIamPolicy` ADMIN_READ entries with resource name | governance service accounts | ADMIN_READ disabled (CF-DR-01) |
| `cloudfox_gcp_content_listing_fanout` | CF-G04, G05 | CF-TEL-08 | DATA_READ list entries with resource name | exporter and backup accounts | DATA_READ disabled (CF-DR-01) |
| `cloudfox_gcp_multi_service_inventory` | CF-G02, G06 | CF-TEL-09 | Data Access entries with serviceName | SCC and CSPM accounts | Partial enablement undercounts (CF-DR-01) |
| `cloudfox_gcp_secret_metadata_multi_project` | CF-G06 | CF-TEL-10 | ListSecrets Data Access entries with principal and project ID | secret-governance accounts | Secret Manager Data Access disabled (CF-DR-01) |
| `cloudfox_cli_module_grammar_execution` | CF-X01 | CF-TEL-11 | PROCESS_LAUNCH with command line | none | Tool run from operator infrastructure leaves no host record; no command-line capture means no match (CF-DR-12) |

## Deployment order

1. Rules that work with default logging:
   - AWS rules, where management read events are enabled
   - `cloudfox_azure_app_settings_secret_list`
   - `cloudfox_gcp_bigquery_select_star_sampling`
2. Enable GCP ADMIN_READ and DATA_READ logging and Azure storage diagnostics where cost allows. Then enable the dependent breadth rules.
3. Add ARM read-plane telemetry if a source exists.

## Validation checklist

- [x] Every current YARA-L rule appears in the rule matrix.
- [ ] Field placement of eventSource, requestParameters, principalEmail and caller was verified in the tenant.
- [ ] Data Access and diagnostic settings were inventoried per project and subscription.
- [ ] CSPM, governance and console negatives were baselined.

## Unresolved telemetry gaps

- Default-disabled read logging (CF-DR-01) is a tenant property, not open backlog. Each dependent rule names the setting it requires.
