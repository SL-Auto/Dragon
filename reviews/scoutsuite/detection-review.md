# ScoutSuite adversarial detection-logic review

## Review scope

- Revision `7909f2fc6186063e5c9e7ddef8c4d7d1072c8f3d`, procedures SS-P01 to SS-P06 in `reports/scoutsuite/source-analysis.md`.
- 7 rules under `detections/scoutsuite/yaral/`.
- Method: every rule was assumed wrong until supported. User-agent placement, breadth thresholds, Kubernetes audit fields and launch grammar were traced against the provider facades and CLI parser.

## Overall assessment

The self-identifying user agent is the strongest signal wherever the audit log records user agents: CloudTrail, GCP `callerSuppliedUserAgent`, OCI and Alibaba. The secret-bearing reads (AWS user data with the credential report, Kubernetes Secrets) are high value. Breadth rules overlap posture platforms. No blocker remains.

## Findings

### SS-DR-01 — Azure ARM reads and DigitalOcean reads leave no default record

- Severity: `high`
- Rules: `scoutsuite_azure_arm_read_fanout`, `scoutsuite_user_agent_in_cloud_audit`
- Assumption challenged: that every provider records the reads and their user agent.
- Gap or failure mode: the Azure Activity Log omits reads, so the ScoutSuite user agent on ARM reads is not recorded by default. DigitalOcean offers no read audit at all.
- Resolution: `accepted_gap`, inherent to the providers. Compensating signals: ARM read-plane telemetry where available, Entra sign-in for the token, and `scoutsuite_cli_execution` on monitored hosts. DigitalOcean audits are recorded as observable only through launch.

### SS-DR-02 — the user-agent string can be removed by a modified build

- Severity: `low`
- Rule: `scoutsuite_user_agent_in_cloud_audit`
- Gap or failure mode: `get_user_agent()` is hard-coded, but an operator can edit it.
- Resolution: `accepted_gap`. The breadth and secret-read rules do not depend on it.

### SS-DR-03 — Kubernetes controllers list Secrets cluster-wide

- Severity: `medium`
- Rule: `scoutsuite_kubernetes_cluster_wide_secret_and_resource_list`
- Gap or failure mode: backup (Velero), GitOps and admission controllers list Secrets and many kinds.
- Resolution: `accepted_gap`. The rule requires Secrets plus ten or more other kinds within 10 minutes by one user. Controllers' service accounts should be allowlisted.

### SS-DR-04 — breadth thresholds overlap CSPM

- Severity: `medium`
- Rules: `scoutsuite_aws_multi_service_read_fanout`, `scoutsuite_gcp_multi_service_read_fanout`, `scoutsuite_azure_arm_read_fanout`
- Gap or failure mode: posture platforms are indistinguishable by breadth.
- Resolution: `accepted_gap`. Medium severity with CSPM allowlisting. The user-agent rule separates ScoutSuite where it is recorded.

### SS-DR-05 — the CLI grammar collides with other scout commands

- Severity: `low`
- Rule: `scoutsuite_cli_execution`
- Gap or failure mode: other tools named `scout` could take an `aws` or `gcp` argument.
- Resolution: `fixed` in design. A provider subcommand must immediately follow the `scout` token, or the module form `-m ScoutSuite` must appear. Medium severity.

## Not observable or excluded

- The report renderer and rule engine are excluded (local processing).
- DigitalOcean reads are not observable in the victim account (SS-DR-01).

## Re-review

- All 7 rules were re-traced.
- Thresholds are computed in `outcome`, joins are on principal, and exclusions fail open.
- No unresolved `blocker` remains.

## Required follow-up

- Confirm user-agent field placement for CloudTrail and Cloud Audit (`callerSuppliedUserAgent`).
- Enable Kubernetes control-plane audit logging.
- Allowlist CSPM identities.
- Keep all rules experimental.
