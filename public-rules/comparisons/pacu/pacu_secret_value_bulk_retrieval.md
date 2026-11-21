# Public-rule comparison: pacu_secret_value_bulk_retrieval

## Identity and independence gate

- Internal tool: `pacu` (revision `7dd34aa0856b2a964763a70be9dc9d78abc08a81`)
- Internal canonical rule: `detections/pacu/yaral/pacu_secret_value_bulk_retrieval.yaral`
- Internal SHA-256: `661be4991a0c696cfe8a7fd5b023b2cdcf4f94812c6931c095141341123c4a9d`
- Internal review completed before public comparison: `yes` (`reviews/pacu/detection-review.md`, PA-DR-01 to PA-DR-08)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/aws/credential_access_rapid_secret_retrieval_attempts_from_secretsmanager.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/aws/credential_access_rapid_secret_retrieval_attempts_from_secretsmanager.toml) - SHA-256 `791b8ce2094d8ab02772318912ce5deab7741fd218fc96c2ebe3e450182c74a4`
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/aws/credential_access_retrieve_secure_string_parameters_via_ssm.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/aws/credential_access_retrieve_secure_string_parameters_via_ssm.toml) - SHA-256 `f614b9669637c2cdbc5903bde1b827aac734e026f8d41574244f91e7924c62a7`
- Scope mapping rationale: All detect retrieval of secret values (T1555.006): Secrets Manager GetSecretValue volume and first-seen SSM SecureString decryption.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Bulk GetSecretValue by one principal | covered (>= 5 distinct secrets) | covered (threshold on GetSecretValue) | distinct secrets - strong | none | equivalent |
| SSM parameters read with decryption | covered after this comparison (withDecryption required) | covered (new terms) | decrypted SecureString read - strong | none | complementary |
| Plain SSM configuration parameters | excluded after this comparison | excluded | withDecryption=false - weak | none | equivalent |

## Missing detection branches

- None.

## Detection edge cases and blind spots

- Rotation and configuration agents.

## Signal-quality assessment

- Ours: distinct secret count across both services - strong.
- Public: per-service thresholds and novelty - moderate.

## Public-rule weaknesses

- Browser user-agent exclusions are spoofable.

## Internal-rule weaknesses

- Before this comparison, plain parameter reads counted.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/pacu/source-analysis.md`, `telemetry/pacu.md` and `reviews/pacu/detection-review.md`.
- Decision: `modify`.
- Reason: the branch is real; the adopted rule diverges from the proposal as follows:
  - SSM reads now require `withDecryption=true`, and service-invoked calls are excluded (PA-DR-09).
  - Browser user-agent exclusions are rejected as attacker-controlled.
- Canonical result: `detections/pacu/yaral/pacu_secret_value_bulk_retrieval.yaral`, SHA-256 `661be4991a0c696cfe8a7fd5b023b2cdcf4f94812c6931c095141341123c4a9d`.
- Regeneration: canonical patch; regenerated in the same run: detection review, `telemetry/pacu.md`, `telemetry/MASTER.md` counts, native translations, dependency and manifest hashes, and this re-comparison.

## Unmatched scope

None. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: Decryption requirement for SSM reads.
- Required telemetry: CloudTrail SSM and Secrets Manager reads with withDecryption.
- Validation status: `unvalidated_proposal`

```yaral
rule pacu_ssm_secure_string_read {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PA-P08"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.product_event_type = /^(GetParameter|GetParameters)$/
    $e.additional.fields["withDecryption"] = "true"
    $e.principal.user.userid = $principal
  match:
    $principal over 30m
  condition:
    $e
}
```

## Re-comparison against revised canonical rule

- The adopted rule was re-run against the branch matrix above on 2026-11-21. It closes the targeted branch within declared telemetry; the residual limits are in `reviews/pacu/detection-review.md`.
- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule pacu_secret_value_bulk_retrieval {
  meta:
    author = "Detection Research Agent"
    description = "Detects one principal retrieving five or more distinct secret values within 30 minutes through Secrets Manager GetSecretValue, or SSM GetParameter(s) with decryption, excluding calls invoked by AWS services (PA-DR-09)."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Bulk value retrieval across secrets is credential harvesting; applications usually read a few fixed secrets."
    procedure_ids = "PA-P08"
    log_source_prerequisites = "AWS CloudTrail management events normalized with metadata.product_name = 'AWS CloudTrail', eventName in metadata.product_event_type, userIdentity ARN in principal.user.userid, userAgent in network.http.user_agent and requestParameters in additional.fields; secretId or parameter name in target.resource.name; requestParameters.withDecryption and userIdentity.invokedBy in additional.fields."
    false_positives = "Secret-rotation tooling, migration scripts and configuration-management agents reading many parameters."
    references = "reports/pacu/source-analysis.md#procedure-analysis; reviews/pacu/detection-review.md; public-rules/comparisons/pacu/pacu_secret_value_bulk_retrieval.md"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized retrieval events for five secrets from one ARN; baseline application roles."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/pacu/detection-review.md"
  events:
    $e.metadata.product_name = "AWS CloudTrail"
    (
      $e.metadata.product_event_type = /^(GetSecretValue|BatchGetSecretValue)$/ or
      ($e.metadata.product_event_type = /^(GetParameter|GetParameters|GetParametersByPath)$/ and re.regex($e.additional.fields["withDecryption"], `(?i)^true$`))
    )
    not re.regex($e.additional.fields["invokedBy"], `(?i)(AWS Internal|\.amazonaws\.com)$`)
    $e.principal.user.userid = $principal
    $e.target.resource.name = $secret
  match:
    $principal over 30m
  outcome:
    $secrets = count_distinct($secret)
  condition:
    $e and $secrets >= 5
}
```
