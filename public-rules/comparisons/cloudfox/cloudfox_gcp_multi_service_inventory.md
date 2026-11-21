# Public-rule comparison: cloudfox_gcp_multi_service_inventory

## Identity and independence gate

- Internal tool: `cloudfox` (revision `f65be085cde3768281c2dbafc57542a56ee12ebe`)
- Internal canonical rule: `detections/cloudfox/yaral/cloudfox_gcp_multi_service_inventory.yaral`
- Internal SHA-256: `dabed9e72b45cf5f71a35f58b32b46c14d6a26d88125ed93a262197f6d39429b`
- Internal review completed before public comparison: `yes` (`reviews/cloudfox/detection-review.md`, CF-DR-01 to CF-DR-08)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/gcp/discovery_gcp_secret_manager_listsecrets_across_multiple_projects.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/gcp/discovery_gcp_secret_manager_listsecrets_across_multiple_projects.toml) - SHA-256 `e019cf9fc8426ad1a275b05a181691a4994f495418b7dc106c9fd5b19ce1e875`
- Scope mapping rationale: Both detect GCP reconnaissance by one identity in Cloud Audit Logs. The public rule targets ListSecrets across projects (CF-G06); ours targets service breadth (CF-G02).

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Many services listed by one principal | covered (>= 10 services) | not covered | service breadth - moderate | IAM-policy fan-out - moderate | ours_stronger |
| ListSecrets across many projects | not covered before this comparison | covered | project breadth on Secret Manager - moderate | new multi-project rule | public_stronger |

## Missing detection branches

- Running `secrets` alone never reaches ten services (CF-DR-11).

## Detection edge cases and blind spots

- Secret Manager Data Access logging is disabled by default (CF-DR-01).

## Signal-quality assessment

- Ours: service breadth - moderate.
- Public: project breadth for ListSecrets - moderate.

## Public-rule weaknesses

- It covers only Secret Manager.

## Internal-rule weaknesses

- Service breadth misses a single-service, multi-project sweep.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/cloudfox/source-analysis.md`, `telemetry/cloudfox.md` and `reviews/cloudfox/detection-review.md`.
- Decision: `modify`.
- Reason: the branch is real; the adopted rule diverges from the proposal as follows:
  - The branch is real and is adopted as `cloudfox_gcp_secret_metadata_multi_project`: five or more projects in 30 minutes, with the method matched by suffix to tolerate full or short method names (CF-DR-11).
- Canonical result: `detections/cloudfox/yaral/cloudfox_gcp_secret_metadata_multi_project.yaral`, SHA-256 `4cc4bb882774b7113d08de04328995a80b7ca742b3006e0e23670f58227afe7e`.
- Regeneration: new canonical rule; regenerated in the same run: detection review, coverage, `telemetry/cloudfox.md`, `telemetry/MASTER.md` counts, native translations, dependency and manifest hashes, and this re-comparison.

## Unmatched scope

The public rule does not address other services. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `new_rule`
- Addresses branches: Secret metadata sweep across projects (CF-G06).
- Required telemetry: Secret Manager Data Access audit entries with principal and project ID.
- Validation status: `unvalidated_proposal`

```yaral
rule cloudfox_gcp_listsecrets_many_projects {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "CF-G06"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.product_event_type = "google.cloud.secretmanager.v1.SecretManagerService.ListSecrets"
    $e.principal.user.email_addresses = $principal
    $e.target.cloud.project.name = $project
  match:
    $principal over 30m
  outcome:
    $projects = count_distinct($project)
  condition:
    $e and $projects >= 5
}
```

## Re-comparison against revised canonical rule

- The adopted rule was re-run against the branch matrix above on 2026-11-21. It closes the targeted branch within declared telemetry; the residual limits are in `reviews/cloudfox/detection-review.md`.
- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule cloudfox_gcp_secret_metadata_multi_project {
  meta:
    author = "Detection Research Agent"
    description = "Detects one GCP principal listing Secret Manager secrets in five or more distinct projects within 30 minutes. The secrets module iterates every accessible project, so the cross-project sweep locates secrets before any targeted value access."
    date = "2026-11-21"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "ListSecrets returns no values, but a multi-project sweep is a reconnaissance step toward credential access; secret-inventory and governance tools overlap."
    procedure_ids = "CF-G06"
    log_source_prerequisites = "GCP Cloud Audit Logs Data Access for Secret Manager (ListSecrets is DATA_READ), normalized with methodName in metadata.product_event_type, principalEmail in principal.user.email_addresses and the project ID in target.cloud.project.name."
    false_positives = "Secret-inventory, compliance and governance service accounts that enumerate secrets organization-wide."
    references = "reports/cloudfox/source-analysis.md#procedure-analysis; public-rules/comparisons/cloudfox/cloudfox_gcp_multi_service_inventory.md; reviews/cloudfox/detection-review.md#cf-dr-11"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized ListSecrets audit entries across five projects and confirm Secret Manager Data Access logging is enabled."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/cloudfox/detection-review.md"
  events:
    re.regex($e.metadata.product_event_type, `(?i)SecretManagerService\.ListSecrets$`)
    $e.principal.user.email_addresses = $principal
    $e.target.cloud.project.name = $project
  match:
    $principal over 30m
  outcome:
    $projects = count_distinct($project)
    $source_ips = array_distinct($e.principal.ip)
  condition:
    $e and $projects >= 5
}
```
