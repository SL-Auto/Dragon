# CloudFox adversarial detection-logic review

## Review scope

- Revision `f65be085cde3768281c2dbafc57542a56ee12ebe`, procedures CF-A01 to CF-A07, CF-Z01 to CF-Z05 and CF-G01 to CF-G06 in `reports/cloudfox/source-analysis.md`.
- 15 rules under `detections/cloudfox/yaral/` (6 AWS, 3 Azure, 5 GCP, 1 endpoint), including two added after public comparison (CF-DR-11, CF-DR-12).
- Method: every rule was assumed wrong until supported. Each predicate, field mapping, window, threshold and exclusion was traced against the source's API calls and against default cloud audit logging.

## Overall assessment

CloudFox is read-only apart from BigQuery query jobs, so every signal is an audit-log pattern from a single principal.
- **Strongest:** explicit secret-bearing reads (EC2 user data, App Service settings lists) and templated BigQuery sampling, which are logged by default or are explicit.
- **Weaker:** breadth rules, which depend on read-event or Data Access logging that many tenants disable, and which overlap with posture tooling.

No blocker remains.

## Findings

### CF-DR-01 — read and Data Access logging is frequently disabled

- Severity: `high`
- Rules: `cloudfox_azure_arm_read_fanout`, `cloudfox_gcp_iam_policy_read_fanout`, `cloudfox_gcp_content_listing_fanout`, `cloudfox_gcp_multi_service_inventory`, `cloudfox_azure_storage_listing_fanout`
- Assumption challenged: that read operations are recorded.
- Gap or failure mode:
  - The Azure Activity Log does not record ARM reads.
  - GCP Data Access logs (`ADMIN_READ` and `DATA_READ`) are disabled by default except for BigQuery.
  - Storage data-plane logs need diagnostic settings.
  - Without these, the rules are silent.
- Resolution: `accepted_gap`, inherent to tenant logging. Prerequisites name the exact setting each rule needs. Compensating signals that work with default logging: `cloudfox_azure_app_settings_secret_list` (Activity Log actions) and `cloudfox_gcp_bigquery_select_star_sampling` (BigQuery data access is on by default).

### CF-DR-02 — console browsing inflates the secret-bearing configuration sweep

- Severity: `medium`
- Rule: `cloudfox_aws_secret_bearing_config_sweep`
- Gap or failure mode: Lambda `ListFunctions` and CloudFormation `GetTemplate` fire whenever a user browses those console pages. An administrator could reach three kinds in 30 minutes.
- Resolution: `fixed`. Console and internal user agents (`console.amazonaws.com`, `signin.amazonaws.com`, `AWS Internal`) are excluded. CloudFox uses the AWS SDK for Go, so its own user agent is not excluded.

### CF-DR-03 — single-command use stays under breadth thresholds

- Severity: `medium`
- Rules: `cloudfox_aws_multi_service_enumeration_fanout`, `cloudfox_gcp_multi_service_inventory`, `cloudfox_azure_arm_read_fanout`
- Gap or failure mode: running one command (for example `aws instances`) touches only one or two services.
- Resolution: `accepted_gap`. Lower thresholds collide with ordinary automation. Compensating signals cover the high-value single commands: user-data, secret-configuration, authorization-details, policy-simulation, App Service settings and BigQuery rules.

### CF-DR-04 — principal identity splits across sessions and identities

- Severity: `low`
- Rules: all.
- Gap or failure mode:
  - AWS assumed-role ARNs include the session name, so a tool that rotates sessions splits its count.
  - GCP principals may appear as service accounts or as user principals.
  - Azure callers may be object IDs or UPNs.
- Resolution: `accepted_gap`. CloudFox runs one session per invocation (source: one configured profile or credential). Prerequisites state each field mapping. Cross-session correlation by access key ID is a tenant enrichment.

### CF-DR-05 — App Service portal configuration blade

- Severity: `medium`
- Rule: `cloudfox_azure_app_settings_secret_list`
- Gap or failure mode: opening the Configuration blade in the portal calls the same list action, and the Activity Log carries no user agent to separate portal traffic.
- Resolution: `accepted_gap`. The two-site threshold within 30 minutes reduces single-app administration matches. Severity stays high because every match exposes clear-text secrets. Approve deployment identities in triage.

### CF-DR-06 — governance tools perform identical reads

- Severity: `medium`
- Rules: `cloudfox_aws_authorization_details_dump`, `cloudfox_aws_policy_simulation_fanout`, `cloudfox_gcp_iam_policy_read_fanout`
- Gap or failure mode: CSPM, IAM Access Analyzer-style tools, Policy Analyzer and the IAM console policy simulator issue the same calls.
- Resolution: `accepted_gap`. No tool-identifying field exists in the audit record. False-positive notes direct allowlisting by role ARN or service account. Severity is medium or low for these.

### CF-DR-07 — BigQuery query text normalization

- Severity: `low`
- Rule: `cloudfox_gcp_bigquery_select_star_sampling`
- Assumption challenged: that the parser exposes the query text verbatim.
- Gap or failure mode: some pipelines truncate or redact query text; the method name differs between BigQuery audit log v1 (`jobservice.insert`) and v2 (`google.cloud.bigquery.v2.JobService.InsertJob`).
- Resolution: `fixed` in design. The method regex accepts both forms. The query regex tolerates whitespace and accepts any backtick-quoted three-part table name with a numeric limit. Redacted query text is an accepted gap.

### CF-DR-08 — the CloudTrail history lookup is weak on its own

- Severity: `low`
- Rule: `cloudfox_aws_programmatic_assumerole_history_lookup`
- Gap or failure mode: security analysts and SOAR playbooks query AssumeRole history programmatically.
- Resolution: `accepted_gap`. The rule is low severity and corroborating. Console traffic is excluded.

## Comparison-driven changes (2026-11-21)

The public comparisons ran after the findings above. Each adopted change was reviewed here before canonical adoption.

### CF-DR-09 — console sessions in the multi-service fan-out

- Severity: `medium`
- Rule: `cloudfox_aws_multi_service_enumeration_fanout`
- Gap or failure mode: console browsing across many service pages can reach 15 event sources. The public rule excludes console-session credentials.
- Resolution: `fixed`. The console and internal user-agent exclusion from CF-DR-02 is applied, and it fails open when the user agent is absent. The public rule's 10-second velocity window is not adopted: CloudFox pages through regions and services over minutes, so a 10-second bucket undercounts its breadth.

### CF-DR-10 — AWS service-invoked user-data reads

- Severity: `low`
- Rule: `cloudfox_aws_instance_userdata_bulk_read`
- Gap or failure mode: AWS services (CloudFormation, AWS Internal and similar) can call DescribeInstanceAttribute on a principal's behalf.
- Resolution: `fixed`. Events whose `userIdentity.invokedBy` is `AWS Internal` or an `*.amazonaws.com` service are excluded. The public rule's success-only filter is not adopted: denied user-data reads by an unauthorized principal are also reconnaissance.

### CF-DR-11 — cross-project secret metadata sweep

- Severity: `medium`
- Rule: new `cloudfox_gcp_secret_metadata_multi_project`
- Assumption challenged: that service breadth (`cloudfox_gcp_multi_service_inventory`) covers CF-G06.
- Gap or failure mode: running `secrets` alone touches one service across many projects and never reaches ten services.
- Resolution: `compensating_signal`. `ListSecrets` in five or more projects within 30 minutes by one principal. It requires Secret Manager Data Access logging (CF-DR-01).

### CF-DR-12 — CloudFox executed from a monitored host

- Severity: `medium`
- Rule: new `cloudfox_cli_module_grammar_execution`
- Assumption challenged: that CloudFox is never observable on a host.
- Gap or failure mode: an operator may run CloudFox from a compromised workstation or jump host. The public rule matches the `cloudfox` process name, which renaming defeats.
- Resolution: `compensating_signal`. The rule matches the provider-plus-module grammar, using only module names absent from the AWS CLI, `az` and `gcloud` command trees (for example `aws outbound-assumed-roles`, `azure tokencache`, `gcp hiddenadmins`).
  - Generic modules such as `aws lambda` are excluded deliberately, because they collide with AWS CLI syntax.
  - A new procedure, CF-X01, records this branch.

## Not observable or excluded

- The operator-local commands (`cape`, `tui`, `pmapper`, `graph`, `foxmapper`, `all-checks`) are excluded in the report, because they have no victim-side effect.
- No procedure is `not_observable` within the victim's audit logs. Observability depends on enabled logging (CF-DR-01).

## Re-review of revised rules

- All 15 rules were re-traced after CF-DR-02 and CF-DR-09 to CF-DR-12.
- Single-event aggregations carry the principal as the match key.
- Thresholds are computed in `outcome`, windows are bounded, regexes are anchored where they match identifiers, and exclusions fail open (an absent user agent is not excluded).
- No unresolved `blocker` remains.

## Required follow-up

- Confirm per-tenant UDM placement of CloudTrail `eventSource`, `requestParameters`, GCP `principalEmail` and Azure `caller`.
- Record which Data Access and read-plane logs are enabled, and disable dependent rules where they are not.
- Validate with sanitized audit fixtures, including CSPM and console negatives.
- Keep all rules experimental.
