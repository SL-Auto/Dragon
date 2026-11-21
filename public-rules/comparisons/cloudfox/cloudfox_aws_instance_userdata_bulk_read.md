# Public-rule comparison: cloudfox_aws_instance_userdata_bulk_read

## Identity and independence gate

- Internal tool: `cloudfox` (revision `f65be085cde3768281c2dbafc57542a56ee12ebe`)
- Internal canonical rule: `detections/cloudfox/yaral/cloudfox_aws_instance_userdata_bulk_read.yaral`
- Internal SHA-256: `83024398cfb227fbaadb2ef14dc378755de181ea1ffd53515ef028065bc1245b`
- Internal review completed before public comparison: `yes` (`reviews/cloudfox/detection-review.md`, CF-DR-01 to CF-DR-08)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/aws/discovery_ec2_bulk_user_data_enumeration.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/aws/discovery_ec2_bulk_user_data_enumeration.toml) - SHA-256 `ab0a883fbec6a3fc955b08c284ead8c3a1f8af73dbb84145ffed0dbd487a85a1`
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/aws/discovery_ec2_userdata_request_for_ec2_instance.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/aws/discovery_ec2_userdata_request_for_ec2_instance.toml) - SHA-256 `9cb5c8680d2b1383101c731d8205014657f316822c0d434e5c0f1a53c552bec6`
- Scope mapping rationale: All three detect DescribeInstanceAttribute userData reads in CloudTrail (T1552.005).

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Bulk user-data reads by one principal | covered (>= 3 instances in 30 minutes) | covered (> 20 instances in 10 minutes, same source IP) | explicit attribute - strong | secret-config sweep - strong | ours_stronger |
| First-time single user-data read | not covered | covered by the new-terms rule | novelty - moderate | none | public_stronger |
| Reads invoked by AWS services | excluded after this comparison (`invokedBy`) | excluded | invokedBy - moderate | none | equivalent |
| Denied user-data reads | covered (no outcome filter) | not covered (success only) | attempt visibility - moderate | none | ours_stronger |

## Missing detection branches

- Single-instance targeted reads (the public new-terms rule covers them).

## Detection edge cases and blind spots

- The attribute field mapping varies by parser.

## Signal-quality assessment

- Ours and public: explicit `attribute = userData` - strong.

## Public-rule weaknesses

- The 20-instance threshold misses targeted harvesting; the success filter hides denied attempts; named-vendor exclusions are tenant-specific.

## Internal-rule weaknesses

- Before this comparison, AWS service-invoked reads were not excluded.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/cloudfox/source-analysis.md`, `telemetry/cloudfox.md` and `reviews/cloudfox/detection-review.md`.
- Decision: `modify`.
- Reason: the branch is real; the adopted rule diverges from the proposal as follows:
  - The `invokedBy` exclusion is adopted with a generic `AWS Internal` or `*.amazonaws.com` pattern, not the public rule's vendor role names (CF-DR-10).
  - The success-only filter and the 20-instance threshold are not adopted, so denied and low-volume harvesting stay visible.
- Canonical result: `detections/cloudfox/yaral/cloudfox_aws_instance_userdata_bulk_read.yaral`, SHA-256 `83024398cfb227fbaadb2ef14dc378755de181ea1ffd53515ef028065bc1245b`.
- Regeneration: canonical patch; regenerated in the same run: detection review, coverage, `telemetry/cloudfox.md`, `telemetry/MASTER.md` counts, native translations, dependency and manifest hashes, and this re-comparison.

## Unmatched scope

The public rules' vendor-role exclusions are environment-specific. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: AWS service-invoked user-data reads.
- Required telemetry: CloudTrail DescribeInstanceAttribute with requestParameters.attribute and userIdentity.invokedBy.
- Validation status: `unvalidated_proposal`

```yaral
rule cloudfox_aws_userdata_read_not_service_invoked {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "CF-A05"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.product_event_type = "DescribeInstanceAttribute"
    $e.additional.fields["attribute"] = "userData"
    $e.additional.fields["invokedBy"] != "cloudformation.amazonaws.com"
    $e.security_result.action = "ALLOW"
    $e.principal.user.userid = $principal
    $e.target.resource.name = $instance
  match:
    $principal over 10m
  outcome:
    $instances = count_distinct($instance)
  condition:
    $e and $instances > 20
}
```

## Re-comparison against revised canonical rule

- The adopted rule was re-run against the branch matrix above on 2026-11-21. It closes the targeted branch within declared telemetry; the residual limits are in `reviews/cloudfox/detection-review.md`.
- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule cloudfox_aws_instance_userdata_bulk_read {
  meta:
    author = "Detection Research Agent"
    description = "Detects one AWS principal reading EC2 instance user data (DescribeInstanceAttribute with attribute userData) for three or more instances within 30 minutes, harvesting bootstrap scripts that often embed credentials."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Reading user data across instances is rare outside provisioning tooling and directly exposes embedded secrets."
    procedure_ids = "CF-A05"
    log_source_prerequisites = "AWS CloudTrail management events normalized with metadata.product_name = 'AWS CloudTrail', eventName in metadata.product_event_type, eventSource in target.application, userIdentity ARN in principal.user.userid; requestParameters.attribute in additional.fields['attribute'] and instanceId in target.resource.name; userIdentity.invokedBy in additional.fields['invokedBy'] (calls made by AWS services on a principal's behalf are excluded, CF-DR-10)."
    false_positives = "Configuration-management or migration tooling that inspects user data; approve their role ARNs."
    references = "reports/cloudfox/source-analysis.md#procedure-analysis; reviews/cloudfox/detection-review.md; public-rules/comparisons/cloudfox/cloudfox_aws_instance_userdata_bulk_read.md; reviews/cloudfox/detection-review.md#cf-dr-10"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized DescribeInstanceAttribute userData events for three instances and confirm the attribute field mapping."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/cloudfox/detection-review.md"
  events:
    $e.metadata.product_name = "AWS CloudTrail"
    $e.metadata.product_event_type = "DescribeInstanceAttribute"
    re.regex($e.additional.fields["attribute"], `(?i)^userData$`)
    not re.regex($e.additional.fields["invokedBy"], `(?i)(AWS Internal|\.amazonaws\.com)$`)
    $e.principal.user.userid = $principal
    $e.target.resource.name = $instance
  match:
    $principal over 30m
  outcome:
    $instances = count_distinct($instance)
    $source_ips = array_distinct($e.principal.ip)
  condition:
    $e and $instances >= 3
}
```
