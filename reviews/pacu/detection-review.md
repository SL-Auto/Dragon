# Pacu adversarial detection-logic review

## Review scope

- Revision `7dd34aa0856b2a964763a70be9dc9d78abc08a81`, procedures PA-P01 to PA-P16 in `reports/pacu/source-analysis.md`.
- Rules under `detections/pacu/yaral/`, plus any added after public comparison (see the comparison-driven findings below).
- Method: every rule was assumed wrong until supported. Event names, request-parameter fields, joins, ordering, thresholds and exclusions were traced against each module's API calls.

## Overall assessment

Pacu performs write operations, so most procedures are visible in default CloudTrail management events, and the strongest signals are the write actions themselves:
- IAM modification
- credential backdoors
- detection impairment
- remote-execution chains

Data-plane procedures depend on logging that is often disabled: S3 objects, EBS direct reads, EKS audit. No blocker remains after the fixes below.

## Findings

### PA-DR-01 — data-event logging is often disabled

- Severity: `high`
- Rules: `pacu_s3_bulk_object_download`, `pacu_snapshot_and_database_takeover` (EBS direct branch), `pacu_eks_service_account_token_collection`
- Assumption challenged: that data-plane access is recorded by default.
- Gap or failure mode: S3 data events, EBS direct API data events and EKS control-plane audit logs are disabled by default.
- Resolution: `accepted_gap`, a tenant logging property. Prerequisites name the setting. Compensating signals: the multi-service enumeration fan-out, the snapshot management events (CreateVolume, AttachVolume, Restore) and `DescribeCluster` in CloudTrail.

### PA-DR-02 — infrastructure-as-code overlap on write sequences

- Severity: `medium`
- Rules: `pacu_iam_privilege_modification_burst`, `pacu_eventbridge_lambda_backdoor_chain`, `pacu_ecs_task_definition_run`, `pacu_cognito_pool_abuse`
- Gap or failure mode: CloudFormation, CDK, Terraform and CI pipelines perform the same multi-step writes.
- Resolution: `accepted_gap`. False-positive notes direct allowlisting of deployment role ARNs. Calls made by CloudFormation carry `invokedBy` in CloudTrail and should be excluded in tenant tuning.

### PA-DR-03 — the user-agent suffix is optional

- Severity: `low`
- Rule: `pacu_user_agent_session_suffix`
- Gap or failure mode: the suffix exists only after `set_ua_suffix`. On Kali, Parrot and Pentoo hosts Pacu replaces the OS-identifying user agent instead (`main.py` L1594-1601).
- Resolution: `accepted_gap`. High-confidence attribution when present; absence proves nothing. No rule depends on the replaced user agent's content.

### PA-DR-04 — the Lambda backdoor chain matched ordinary serverless deployments

- Severity: `high`
- Rule: `pacu_eventbridge_lambda_backdoor_chain`
- Assumption challenged: that a function plus an EventBridge rule is unusual.
- Gap or failure mode: CreateFunction plus any PutRule or PutTargets matches every scheduled serverless deployment.
- Resolution: `fixed`. The rule now requires a PutRule whose `eventPattern` targets `aws.iam` or `aws.ec2` API events. This matches the module's patterns on CreateUser, CreateRole and CreateSecurityGroup, and is rare for ordinary applications.

### PA-DR-05 — the snapshot takeover condition referenced a placeholder

- Severity: `blocker` (resolved in this run)
- Rule: `pacu_snapshot_and_database_takeover`
- Gap or failure mode: the condition tested a placeholder value (`$step`). A YARA-L condition cannot reference an event placeholder value, so the rule was invalid.
- Resolution: `fixed`. A `$password_resets` outcome is computed with `max(if(...))` over the events that already matched the MasterUserPassword branch. The condition is `$steps >= 2 or $password_resets > 0`.

### PA-DR-06 — the other-user credential comparison and role callers

- Severity: `medium`
- Rule: `pacu_iam_credential_backdoor_other_user`
- Assumption challenged: that every caller has an IAM user name to compare.
- Gap or failure mode: assumed-role callers have no `userIdentity.userName`. The inequality therefore holds for any role creating credentials for a user.
- Resolution: `accepted_gap`. A role issuing user credentials is itself notable. Self-service key rotation by an IAM user is excluded by the inequality.

### PA-DR-07 — UpdateTrail and UpdateDetector are dual-use

- Severity: `medium`
- Rule: `pacu_detection_service_impairment`
- Gap or failure mode: UpdateTrail and UpdateDetector also make benign configuration changes.
- Resolution: `accepted_gap`. They stay in scope because the module uses them to disable event selectors and detectors. Triage should check `requestParameters` (for example `enable=false`) and change approvals.

### PA-DR-08 — the formula-injection pattern and leading hyphens

- Severity: `low`
- Rule: `pacu_log_formula_injection`
- Gap or failure mode: a bare leading hyphen appears in benign names.
- Resolution: `fixed` in design. The pattern accepts `=`, `+` and `@`, and accepts `-` only when it is followed by a non-hyphen, non-space character.

## Comparison-driven changes (2026-11-21)

### PA-DR-09 — plain SSM parameters inflated secret retrieval

- Severity: `medium`
- Rule: `pacu_secret_value_bulk_retrieval`
- Gap or failure mode: SSM GetParameter(s) without decryption read ordinary configuration values, which applications fetch in bulk.
- Resolution: `fixed`. SSM reads count only with `withDecryption=true`, matching what `secrets__enum` and `systemsmanager__download_parameters` retrieve. Calls invoked by AWS services are excluded. Browser user-agent exclusions from the public rule are not adopted, because the user agent is attacker-controlled.

### PA-DR-10 — service-invoked user-data changes

- Severity: `low`
- Rule: `pacu_instance_userdata_modify_restart`
- Gap or failure mode: CloudFormation and Service Catalog modify instance attributes on a principal's behalf.
- Resolution: `fixed`. Events with `invokedBy` set to an AWS service are excluded. The public rule's Terraform, Ansible and Pulumi user-agent exclusions are rejected, because an attacker can spoof those strings to avoid detection.

## Not observable or excluded

- The operator-local modules and attacker-account-only probing are excluded in the report.
- No in-scope procedure is `not_observable`. Observability of the data-plane procedures depends on enabled logging (PA-DR-01).

## Re-review of revised rules

- All rules were re-traced after PA-DR-04 and PA-DR-05.
- Multi-event rules join on principal (and on instance for user data), ordered sequences enforce order, thresholds are computed in `outcome`, and exclusions fail open.
- No unresolved `blocker` remains.

## Required follow-up

- Confirm the UDM placement of `requestParameters` (userName, attribute, eventPattern, ipPermissions, name), `errorCode` and `invokedBy`.
- Record which data events and EKS audit logs are enabled.
- Baseline deployment roles.
- Keep all rules experimental.
