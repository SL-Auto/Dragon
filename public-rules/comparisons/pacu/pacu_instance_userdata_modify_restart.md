# Public-rule comparison: pacu_instance_userdata_modify_restart

## Identity and independence gate

- Internal tool: `pacu` (revision `7dd34aa0856b2a964763a70be9dc9d78abc08a81`)
- Internal canonical rule: `detections/pacu/yaral/pacu_instance_userdata_modify_restart.yaral`
- Internal SHA-256: `6a806aec71cc342d340c80a7b9cb80a69f62135c907bb6ba78955d151ed9a581`
- Internal review completed before public comparison: `yes` (`reviews/pacu/detection-review.md`, PA-DR-01 to PA-DR-08)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/aws/execution_ec2_stop_start_with_user_data_modification.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/aws/execution_ec2_stop_start_with_user_data_modification.toml) - SHA-256 `1c6b78c3a6338ec957703914c8a932dda6e63abc70b778b0fd457441c7aaf866`
- Scope mapping rationale: Both detect EC2 user-data modification combined with an instance restart (T1059, T1098).

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| User data modified, then instance started | covered (same principal and instance, ordered) | covered (stop, modify and start by one principal) | modify plus start - strong | none | equivalent |
| Service-invoked changes (CloudFormation, Service Catalog) | excluded after this comparison (invokedBy) | excluded (source address) | invokedBy - moderate | none | equivalent |
| Changes made with IaC user agents | not excluded (user agent is spoofable) | excluded | user agent - weak | none | ours_stronger |

## Missing detection branches

- None.

## Detection edge cases and blind spots

- Attribute field normalization.

## Signal-quality assessment

- Both: modify-and-restart sequence - strong.

## Public-rule weaknesses

- Excludes Terraform, Ansible and Pulumi user agents, which an attacker can spoof.

## Internal-rule weaknesses

- Before this comparison, service-invoked changes were not excluded.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/pacu/source-analysis.md`, `telemetry/pacu.md` and `reviews/pacu/detection-review.md`.
- Decision: `modify`.
- Reason: the branch is real; the adopted rule diverges from the proposal as follows:
  - The service-invoked exclusion is adopted through `userIdentity.invokedBy` (PA-DR-10).
  - The user-agent exclusions are rejected, because they create a spoofable false-negative path.
- Canonical result: `detections/pacu/yaral/pacu_instance_userdata_modify_restart.yaral`, SHA-256 `6a806aec71cc342d340c80a7b9cb80a69f62135c907bb6ba78955d151ed9a581`.
- Regeneration: canonical patch; regenerated in the same run: detection review, `telemetry/pacu.md`, `telemetry/MASTER.md` counts, native translations, dependency and manifest hashes, and this re-comparison.

## Unmatched scope

None. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: Service-invoked user-data changes.
- Required telemetry: CloudTrail ModifyInstanceAttribute with invokedBy.
- Validation status: `unvalidated_proposal`

```yaral
rule pacu_userdata_restart_iac_excluded {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PA-P09"
    source_comparison = "unvalidated_proposal"
  events:
    $m.metadata.product_event_type = "ModifyInstanceAttribute"
    not re.regex($m.network.http.user_agent, `(?i)(Terraform|Ansible|Pulumi)`)
    $m.principal.user.userid = $principal
    $s.metadata.product_event_type = "StartInstances"
    $s.principal.user.userid = $principal
  match:
    $principal over 30m
  condition:
    $m and $s
}
```

## Re-comparison against revised canonical rule

- The adopted rule was re-run against the branch matrix above on 2026-11-21. It closes the targeted branch within declared telemetry; the residual limits are in `reviews/pacu/detection-review.md`.
- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule pacu_instance_userdata_modify_restart {
  meta:
    author = "Detection Research Agent"
    description = "Detects one principal modifying an EC2 instance's user data and starting that instance within 30 minutes, which executes the new user data at boot."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Replacing user data and restarting is a direct code-execution path on the instance."
    procedure_ids = "PA-P09"
    log_source_prerequisites = "AWS CloudTrail management events normalized with metadata.product_name = 'AWS CloudTrail', eventName in metadata.product_event_type, userIdentity ARN in principal.user.userid, userAgent in network.http.user_agent and requestParameters in additional.fields; requestParameters attribute in additional.fields['attribute'] and instanceId in target.resource.name; userIdentity.invokedBy in additional.fields (service-invoked changes excluded, PA-DR-10)."
    false_positives = "Configuration changes during maintenance by instance owners."
    references = "reports/pacu/source-analysis.md#procedure-analysis; reviews/pacu/detection-review.md; public-rules/comparisons/pacu/pacu_instance_userdata_modify_restart.md"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized ModifyInstanceAttribute (userData) and StartInstances events for one instance."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/pacu/detection-review.md"
  events:
    $m.metadata.product_name = "AWS CloudTrail"
    $m.metadata.product_event_type = "ModifyInstanceAttribute"
    re.regex($m.additional.fields["attribute"], `(?i)userData`)
    not re.regex($m.additional.fields["invokedBy"], `(?i)(AWS Internal|\.amazonaws\.com)$`)
    $m.principal.user.userid = $principal
    $m.target.resource.name = $instance

    $s.metadata.product_name = "AWS CloudTrail"
    $s.metadata.product_event_type = "StartInstances"
    $s.principal.user.userid = $principal
    $s.target.resource.name = $instance

    $m.metadata.event_timestamp.seconds <= $s.metadata.event_timestamp.seconds
  match:
    $principal, $instance over 30m
  outcome:
    $source_ips = array_distinct($m.principal.ip)
  condition:
    $m and $s
}
```
