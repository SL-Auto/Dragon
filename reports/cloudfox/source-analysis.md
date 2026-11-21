---
title: CloudFox comprehensive source analysis
domain: tool-analysis
type: evidence
authority: reference
---

# CloudFox comprehensive source analysis

## Scope and safety

- **Revision:** static analysis of official revision `f65be085cde3768281c2dbafc57542a56ee12ebe` (`v2.0.5-11-gf65be08`, committed 2026-11-02) from <https://github.com/BishopFox/cloudfox>, accessed 2026-11-21.
- **Handling:** the source was cloned to `sources/cloudfox-src/` (gitignored). It was not built or run, and the checkout contains no binaries.
- **Eligibility:** CloudFox runs on the operator's own machine with credentials for the victim's AWS, Azure or GCP environment. Its effects are API calls that the victim cloud records in its audit logs (CloudTrail, Azure Activity and Graph activity logs, storage logs, Cloud Audit Logs). Those victim-side records are the analyzed surface, consistent with AzureHound under BloodHound.
- **Excluded as operator-local (no victim-observable effect):**
  - `aws cape`, `aws tui` and `cape-tui.go`: offline privilege-escalation graph analysis and terminal UI.
  - `aws pmapper` and `gcp foxmapper`: these read local PMapper/FoxMapper graph files (`gcp/commands/foxmapper.go` L518-526).
  - `aws graph`: Cypher export of locally collected data.
  - `all-checks`: orchestration of other commands only.

## Completeness inventory

All commands registered in `cli/aws.go` (38), `cli/azure.go` (10) and `gcp/commands/` (68 files) were mapped. The cloud API surface was extracted from every non-test Go file, including the `aws/sdk`, `azure`, `internal` and `gcp/services` wrappers.

- **AWS:** read-only. The only non-List/Get/Describe calls are CloudTrail `LookupEvents`, IAM `SimulatePrincipalPolicy` and CodeBuild `BatchGetProjects`; all other Set/Add/Update symbols are local graph and UI code.
- **Azure:** reads, plus the POST `list` actions for app settings and connection strings.
- **GCP:** reads, plus one write-type call. BigQuery `Jobs.Insert` creates a query job that samples table data (`gcp/services/bigqueryEnumService/bigqueryEnumService.go` L153-170).
- No command creates credentials, changes IAM, assumes roles or reads secret values. AWS `secrets` and GCP `secrets` list metadata only (`ListSecrets`, `DescribeParameters`; `secretsService.go` L28-142).

| Procedure | Commands |
| --- | --- |
| CF-A01 | every AWS command (`sts:GetCallerIdentity`), `orgs` |
| CF-A02 | `principals`, `permissions`, `access-keys`, `role-trusts`, `resource-trusts`, `ram` |
| CF-A03 | `iam-simulator`, `role-trusts` |
| CF-A04 | `inventory`, `instances`, `elastic-network-interfaces`, `network-ports`, `endpoints`, `api-gw`, `buckets`, `databases`, `filesystems`, `ecr`, `eks`, `ecs-tasks`, `lambda`, `route53`, `sqs`, `sns`, `tags`, `workloads`, `ds`, `cloudformation`, `codebuild` |
| CF-A05 | `env-vars`, `instances` (user data), `cloudformation` (templates), `codebuild` (project environment) |
| CF-A06 | `secrets` |
| CF-A07 | `outbound-assumed-roles` |
| CF-Z01 | `whoami`, `tokencache` |
| CF-Z02 | `rbac` |
| CF-Z03 | `inventory`, `vms`, `acr`, `func` (listing) |
| CF-Z04 | `func` (settings and connection strings), `automation` (runbook content), `vms` (user data) |
| CF-Z05 | `storage` |
| CF-G01 | `iam`, `serviceaccounts`, `keys`, `permissions`, `privesc`, `lateralmovement`, `hiddenadmins`, `resourceiam`, `organizations`, `orgpolicies`, `workloadidentity`, `identityfederation`, `domainwidedelegation`, `serviceagents`, `whoami`, `crossproject` |
| CF-G02 | all other GCP inventory commands (for example `instances`, `gke`, `functions`, `cloudrun`, `cloudsql`, `buckets`, `pubsub`, `dns`, `firewall`, `kms`, `assetinventory`, `bigtableenum` and `spannerenum` schema scans) |
| CF-G03 | `bigqueryenum` |
| CF-G04 | `logenum` |
| CF-G05 | `bucketenum` |
| CF-G06 | `secrets` |
| CF-X01 | every command, when CloudFox runs on a monitored endpoint |

## Procedure analysis

| ID | Procedure | Ordered behavior and cloud interfaces | Security effect | Victim-side telemetry and gaps | ATT&CK | Confidence |
| --- | --- | --- | --- | --- | --- | --- |
| CF-A01 | AWS identity and organization context | `sts:GetCallerIdentity` at start of each command; `organizations:DescribeOrganization`, `ListAccounts` | Establishes account and organization scope | CloudTrail management events (read events must be enabled); GetCallerIdentity is ubiquitous | T1087.004, T1580 | High |
| CF-A02 | AWS IAM and trust enumeration | `iam:GetAccountAuthorizationDetails`, `ListUsers`, `ListRoles`, `ListAccessKeys`, role trust policies; resource policies (S3 `GetBucketPolicy`, SQS/SNS attributes, KMS `GetKeyPolicy`, Secrets Manager `GetResourcePolicy`, ECR `GetRepositoryPolicy`); RAM shares | Full IAM and cross-account trust map | CloudTrail read events by one principal across IAM and many services | T1087.004, T1069.003 | High |
| CF-A03 | AWS policy simulation | `iam:SimulatePrincipalPolicy` for many principals and actions | Computes who can perform sensitive actions | CloudTrail `SimulatePrincipalPolicy` with differing `policySourceArn` | T1069.003 | High |
| CF-A04 | AWS multi-service inventory | `ec2:Describe*`, ELB, Route 53, API Gateway, Lambda, EKS, ECS, App Runner, Lightsail, RDS, DynamoDB, OpenSearch, EFS, ECR, SQS, SNS, CloudFormation and CodeBuild listing, across regions | Maps the attack surface | CloudTrail read events; the distinctive feature is breadth (many event sources in a short window) | T1580, T1526 | High |
| CF-A05 | AWS secret-bearing configuration reads | `ec2:DescribeInstanceAttribute` with `attribute=userData` per instance (`aws/sdk/ec2.go` L85-120); Lambda `ListFunctions` environment variables; `ecs:DescribeTaskDefinition`; `codebuild:BatchGetProjects`; `cloudformation:GetTemplate` | Harvests credentials embedded in user data, environment variables and templates | CloudTrail; `requestParameters.attribute = userData` is explicit. Lambda environment variables arrive inside ordinary `ListFunctions` | T1552.005, T1552.001 | High |
| CF-A06 | AWS secret inventory (metadata) | `secretsmanager:ListSecrets`, `ssm:DescribeParameters` | Locates secrets without reading values | CloudTrail read events | T1580 | High |
| CF-A07 | AWS CloudTrail history lookup | `cloudtrail:LookupEvents` with `EventName = AssumeRole` over a lookback window (`outbound-assumed-roles.go` L341-349, L434) | Learns which roles were assumed from the account | CloudTrail `LookupEvents` with lookup attributes; the console's Event history also calls it | T1087.004 | High |
| CF-Z01 | Azure tenant and subscription context | Tenants, subscriptions and resource groups through the operator's CLI session | Scope discovery | Entra sign-in for the token; ARM reads are not in the Activity Log by default | T1526 | High |
| CF-Z02 | Azure RBAC and directory users | Microsoft Graph users; ARM role assignments and definitions | Maps privileged principals | `MicrosoftGraphActivityLogs` (diagnostic setting required); ARM reads need read-plane telemetry | T1087.004, T1069.003 | High |
| CF-Z03 | Azure resource inventory | ARM resources list pager, VMs, NICs, public IPs, ACR, web apps and functions | Maps the attack surface | ARM read-plane telemetry only (not the default Activity Log) | T1580, T1526 | High |
| CF-Z04 | Azure secret-bearing reads | Web Apps `ListApplicationSettings` and `ListConnectionStrings` (POST `config/list` actions, `azure/functions.go`); Automation runbook `GetContent`; VM `Get` with `$expand=userData` (`azure/vms.go` L268) | Harvests secrets from app settings, runbooks and user data | The POST list actions are recorded in the Azure Activity Log (`Microsoft.Web/sites/config/list/action`). Runbook content and user-data GETs need read-plane telemetry | T1552.001, T1552.005 | High |
| CF-Z05 | Azure storage container and blob listing | Data-plane `ListContainers` and `ListBlobsFlat` pagers (`azure/storage.go`) | Finds exposed data | `StorageBlobLogs` (diagnostic setting required) | T1619 | High |
| CF-G01 | GCP IAM and identity enumeration | `getIamPolicy` on projects, folders, organizations and resources (55 call sites); `getAncestry`; service accounts and keys listing; org policies; workload identity | Full IAM map and escalation paths | Cloud Audit Logs `ADMIN_READ` Data Access (disabled by default for most services) | T1087.004, T1069.003 | High |
| CF-G02 | GCP multi-service inventory | Cloud Asset `SearchAllResources` and per-service list calls across about 50 services; Bigtable and Spanner schema names | Maps the attack surface | Data Access logs per service (mostly disabled by default); breadth across `serviceName` is the distinctive feature | T1580, T1526 | High |
| CF-G03 | GCP BigQuery data sampling | For flagged tables, `jobs.insert` of `SELECT * FROM \`project.dataset.table\` LIMIT n`, then polling and reading results | Reads table contents | BigQuery `DATA_READ` audit logs (enabled by default), including the query text | T1530, T1213 | High |
| CF-G04 | GCP log-entry scanning | `logging.entries.list` across logs, matched against credential patterns | Reads log contents for secrets | Logging Data Access logs (disabled by default) | T1552, T1530 | High |
| CF-G05 | GCP bucket object listing | `storage.objects.list` across buckets, matching sensitive object names | Finds credential-like files | Cloud Storage `DATA_READ` logs (disabled by default) | T1619 | High |
| CF-G06 | GCP secret inventory (metadata) | Secret Manager list and get of secret metadata | Locates secrets without reading values | Data Access logs | T1580 | High |
| CF-X01 | CloudFox execution on a monitored endpoint | The operator launches `cloudfox <provider> <module>` (provider is aws, azure or gcp) with flags; the provider and module tokens come from `cli/aws.go`, `cli/azure.go` and `gcp/commands` | When run from a compromised or monitored host, the launch exposes the tool and the targeted cloud | Process creation with command line on that host; not visible when run from operator infrastructure | T1059, T1580 | High |

## Observed facts versus inference

- **Observed:** every API call named above, the read-only nature of AWS and Azure operations, the BigQuery `SELECT * ... LIMIT` text, the `AssumeRole` lookup filter and per-instance user-data reads.
- **Inference:**
  - Breadth thresholds (distinct services per principal per window) are detection hypotheses, not source facts.
  - Field placement of CloudTrail `eventSource`, GCP `serviceName` and Azure `caller` in UDM depends on the tenant parser.
