# Public-rule comparison: cloudfox_aws_authorization_details_dump

## Identity and independence gate

- Internal tool: `cloudfox` (revision `f65be085cde3768281c2dbafc57542a56ee12ebe`)
- Internal canonical rule: `detections/cloudfox/yaral/cloudfox_aws_authorization_details_dump.yaral`
- Internal SHA-256: `690bc35e98ecbb6c9d4d16250e44d0ff68e082aeb325479ba3a908f61fd09af8`
- Internal review completed before public comparison: `yes` (`reviews/cloudfox/detection-review.md`, CF-DR-01 to CF-DR-08)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/cross-platform/discovery_cloud_offensive_framework_execution.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/cross-platform/discovery_cloud_offensive_framework_execution.toml) - SHA-256 `93365a0cb2ad19351acd10f7623cee4aa5611f70f313a9f1b7c25c23d45b4df8`
- Scope mapping rationale: Both target CloudFox reconnaissance. The public rule fires when a known cloud-offensive tool executes on an endpoint; ours fires on the IAM authorization dump in CloudTrail.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Full IAM dump in CloudTrail | covered | not covered | GetAccountAuthorizationDetails - moderate | service fan-out - moderate | ours_stronger |
| CloudFox launched on a monitored endpoint | not covered before this comparison | covered by process name | process name - weak (renaming) | module-grammar rule - strong | public_stronger |

## Missing detection branches

- Endpoint execution was absent from our rules (CF-X01).

## Detection edge cases and blind spots

- The public rule is defeated by renaming the binary.

## Signal-quality assessment

- Public: process name - weak.
- Adopted: provider-plus-module command-line grammar - strong.

## Public-rule weaknesses

- Name-based matching of a long list of tools.

## Internal-rule weaknesses

- No host-side signal for an operator working from a monitored host.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/cloudfox/source-analysis.md`, `telemetry/cloudfox.md` and `reviews/cloudfox/detection-review.md`.
- Decision: `modify`.
- Reason: the branch is real; the adopted rule diverges from the proposal as follows:
  - The branch is real. It is adopted as `cloudfox_cli_module_grammar_execution`, which matches CloudFox's provider-plus-module grammar instead of the file name.
  - It uses only module names that do not collide with the AWS CLI, `az` or `gcloud` (CF-DR-12). A new procedure, CF-X01, is recorded.
- Canonical result: `detections/cloudfox/yaral/cloudfox_cli_module_grammar_execution.yaral`, SHA-256 `b4c82d0e373d926fd5f3a9b939458e78b87f5899858524c7ed17a96272d6aa7f`.
- Regeneration: new canonical rule; regenerated in the same run: detection review, coverage, `telemetry/cloudfox.md`, `telemetry/MASTER.md` counts, native translations, dependency and manifest hashes, and this re-comparison.

## Unmatched scope

The public rule also lists many other cloud-offensive tools. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `new_rule`
- Addresses branches: CloudFox launched on a monitored endpoint (CF-X01).
- Required telemetry: Process creation with full command line.
- Validation status: `unvalidated_proposal`

```yaral
rule cloudfox_process_name_execution {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "CF-X01"
    source_comparison = "unvalidated_proposal"
  events:
    $p.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($p.target.process.file.full_path, `(?i)[\\/]cloudfox(\.exe)?$`)
  condition:
    $p
}
```

## Re-comparison against revised canonical rule

- The adopted rule was re-run against the branch matrix above on 2026-11-21. It closes the targeted branch within declared telemetry; the residual limits are in `reviews/cloudfox/detection-review.md`.
- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule cloudfox_cli_module_grammar_execution {
  meta:
    author = "Detection Research Agent"
    description = "Detects a process launched with CloudFox's provider-plus-module argument grammar (for example aws outbound-assumed-roles, aws env-vars, azure tokencache, gcp hiddenadmins) on a monitored endpoint. The grammar survives renaming the binary and uses module names that do not collide with the AWS, Azure or gcloud CLIs."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "When the operator runs CloudFox from a compromised or monitored host, the launch itself is visible; the module names are specific to the tool's command tree in cli/aws.go, cli/azure.go and gcp/commands."
    procedure_ids = "CF-X01"
    log_source_prerequisites = "PROCESS_LAUNCH telemetry (Sysmon Event ID 1, Security 4688 with command line, Linux auditd EXECVE or EDR) with the full command line and image path."
    false_positives = "Authorized cloud security assessments; internal wrappers that reuse CloudFox module names."
    references = "reports/cloudfox/source-analysis.md#completeness-inventory; public-rules/comparisons/cloudfox/cloudfox_aws_authorization_details_dump.md; reviews/cloudfox/detection-review.md#cf-dr-12"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized command lines for each provider prefix and confirm AWS CLI, az and gcloud command lines do not match."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/cloudfox/detection-review.md"
  events:
    $p.metadata.event_type = "PROCESS_LAUNCH"
    $p.principal.hostname = $host
    re.regex($p.target.process.command_line, `(?i)(^|\s)(aws\s+(all-checks|access-keys|api-gw|env-vars|filesystems|iam-simulator|ecs-tasks|elastic-network-interfaces|network-ports|outbound-assumed-roles|principals|resource-trusts|role-trusts|workloads|cape|pmapper)|azure\s+(whoami|tokencache|rbac|automation)|gcp\s+(all-checks|hiddenadmins|privesc|lateralmovement|dataexfiltration|foxmapper|bucketenum|logenum|bigqueryenum|domainwidedelegation|workloadidentity))(\s|$)`)
    $p.target.process.file.full_path = $image
  match:
    $host, $image over 1h
  outcome:
    $command_lines = array_distinct($p.target.process.command_line)
    $users = array_distinct($p.principal.user.userid)
  condition:
    $p
}
```
