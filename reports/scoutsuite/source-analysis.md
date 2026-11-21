---
title: ScoutSuite comprehensive source analysis
domain: tool-analysis
type: evidence
authority: reference
---

# ScoutSuite comprehensive source analysis

## Scope and safety

- **Revision:** static analysis of official revision `7909f2fc6186063e5c9e7ddef8c4d7d1072c8f3d` (committed 2024-05-10, the latest upstream) from <https://github.com/nccgroup/ScoutSuite>, accessed 2026-11-21.
- **Handling:** shallow source clone to `sources/scoutsuite-src/` (gitignored), not built or run. The HTML report asset archive `ScoutSuite/output/data/includes.zip` was deleted unopened under the archive policy.
- **Eligibility:** ScoutSuite runs on the operator machine, or on a monitored host, with cloud credentials. Its read calls are recorded in victim cloud audit logs, and its launch is visible on a monitored host.
- **Excluded:**
  - The HTML report renderer and rule engine (`ScoutSuite/output`, `ScoutSuite/core/rule*`, `providers/*/rules`): local processing of collected data.
  - `tools/`, `docker/` and `tests/`: development and packaging material.

## Completeness inventory

Every provider registered in `ScoutSuite/core/cli_parser.py` (aws L36, gcp L96, azure L135, aliyun L219, oci L247, do L260, kubernetes L286 with aks, eks and gke) and every provider facade was mapped:

| Provider | Python files | Facade surface |
| --- | --- | --- |
| aws | 160 | boto3 paginated List/Describe/Get across services (`facade/utils.py` `get_all_pages`); `generate_credential_report` and `get_credential_report`; `describe_instance_attribute(userData)` per instance (`facade/ec2.py` L26); `list_secrets` (metadata only) |
| azure | 103 | ARM management clients and Graph for directory objects |
| gcp | 89 | Google API discovery clients and Cloud Storage and KMS gapic clients |
| kubernetes | 20 | dynamic client listing every discovered resource kind cluster-wide, including Secrets with their data (`facade/core.py` L19-56) |
| oci | 26 | OCI SDK read clients |
| aliyun | 45 | Alibaba Cloud SDK read requests |
| do | 31 | DigitalOcean API and Spaces through the S3 API |

- The AWS, Azure and GCP clients set the user agent `Scout Suite/<version> (https://github.com/nccgroup/ScoutSuite)`:
  - `utils.py` L111-112
  - AWS: `authentication_strategy.py` L53-55
  - Azure: `user_agent=get_user_agent()` in every facade
  - GCP: `basefacade.py` L34-39 and `cloudstorage.py` L12
- No write API is called. The `set_*` and `update` symbols are request-object setters and local dictionary operations.

## Procedure analysis

| ID | Procedure | Ordered behavior and interfaces | Security effect | Telemetry and gaps | ATT&CK | Confidence |
| --- | --- | --- | --- | --- | --- | --- |
| SS-P01 | AWS configuration audit | Paginated reads across services in every region; credential report generation and retrieval; per-instance user-data reads | Full security-configuration map and embedded secrets | CloudTrail read and management events with the ScoutSuite user agent | T1580, T1526, T1552.005 | High |
| SS-P02 | Azure configuration audit | ARM reads across subscriptions; Graph directory reads; Key Vault metadata | Configuration and identity map | ARM reads need read-plane telemetry; sign-in logs for the token; Graph activity logs | T1580, T1526, T1087.004 | High |
| SS-P03 | GCP configuration audit | Resource Manager, IAM, Compute, Storage, KMS, SQL and other reads | Configuration and IAM map | Cloud Audit Logs Data Access (`callerSuppliedUserAgent` carries the user agent) | T1580, T1526 | High |
| SS-P04 | Kubernetes configuration audit | Discovers API resources and lists every kind cluster-wide, including Secrets with data | Cluster map and secret exposure | Kubernetes API audit logs (EKS, AKS and GKE control-plane logging) | T1613, T1552.007 | High |
| SS-P05 | OCI, Alibaba and DigitalOcean audits | Read requests through each provider SDK | Configuration maps | OCI Audit and Alibaba ActionTrail record user agents; DigitalOcean offers no read audit | T1580 | Medium |
| SS-P06 | Execution on a monitored host | `scout <provider> ...` or `python scout.py <provider> ...` | Visible launch | Process creation with command line | T1059, T1580 | High |

## Observed facts versus inference

- **Observed:** providers, user-agent strings, the credential-report, user-data and Kubernetes Secret reads, and the absence of write calls.
- **Inference:** breadth thresholds are detection hypotheses; OCI and Alibaba user-agent recording follows provider documentation.
