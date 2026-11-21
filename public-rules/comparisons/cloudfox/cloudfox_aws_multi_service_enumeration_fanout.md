# Public-rule comparison: cloudfox_aws_multi_service_enumeration_fanout

## Identity and independence gate

- Internal tool: `cloudfox` (revision `f65be085cde3768281c2dbafc57542a56ee12ebe`)
- Internal canonical rule: `detections/cloudfox/yaral/cloudfox_aws_multi_service_enumeration_fanout.yaral`
- Internal SHA-256: `2d75f6818e578d22de86e3bdd98395b52599e0c9e26949b20107ae34eb0f61b7`
- Internal review completed before public comparison: `yes` (`reviews/cloudfox/detection-review.md`, CF-DR-01 to CF-DR-08)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/aws/discovery_multiple_discovery_api_calls_via_cli.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/aws/discovery_multiple_discovery_api_calls_via_cli.toml) - SHA-256 `961443d58e2df1614e8ed6d5bcafedce7646b3e24c919cb7146f2b3e0d4d4964`
- Scope mapping rationale: Both detect broad read-only AWS discovery by one identity in CloudTrail (T1580, T1526). The mapping is by observable effect.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Many read-only APIs across services by one principal | covered (>= 15 event sources in 30 minutes) | covered (many distinct discovery APIs from one resource in 10 seconds) | service breadth - moderate | secret-read rules - strong | complementary |
| Console browsing that spans many services | excluded after this comparison (console user agents) | excluded (console session credentials) | user-agent or session flag - moderate | none | equivalent |
| Enumeration paced over minutes across regions | covered (30-minute window) | not covered (10-second buckets) | breadth over time - moderate | none | ours_stronger |
| Burst from a compromised instance role | covered when 15 services are reached | covered (velocity) | velocity - moderate | none | public_stronger |

## Missing detection branches

- Single-command use below 15 services (CF-DR-03).
- Bursts that touch fewer services but many APIs.

## Detection edge cases and blind spots

- Write-only trails omit reads (CF-DR-01).
- Assumed-role session rotation splits counts (CF-DR-04).

## Signal-quality assessment

- Ours: distinct services per principal - moderate.
- Public: distinct APIs per resource per 10 seconds - moderate.

## Public-rule weaknesses

- The 10-second window misses paced enumeration; it relies on a fixed provider list.

## Internal-rule weaknesses

- Before this comparison, console sessions could inflate breadth.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/cloudfox/source-analysis.md`, `telemetry/cloudfox.md` and `reviews/cloudfox/detection-review.md`.
- Decision: `modify`.
- Reason: the branch is real; the adopted rule diverges from the proposal as follows:
  - The console-exclusion branch is real. It is adopted as a user-agent exclusion that fails open, because the UDM record has no portable `session_credential_from_console` field (CF-DR-09).
  - The 10-second velocity window is not adopted, because CloudFox pages across regions and services over minutes.
- Canonical result: `detections/cloudfox/yaral/cloudfox_aws_multi_service_enumeration_fanout.yaral`, SHA-256 `2d75f6818e578d22de86e3bdd98395b52599e0c9e26949b20107ae34eb0f61b7`.
- Regeneration: canonical patch; regenerated in the same run: detection review, coverage, `telemetry/cloudfox.md`, `telemetry/MASTER.md` counts, native translations, dependency and manifest hashes, and this re-comparison.

## Unmatched scope

The public rule also covers non-CloudFox discovery bursts from instances. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: Console-session browsing inflating the breadth count.
- Required telemetry: CloudTrail read events with userAgent.
- Validation status: `unvalidated_proposal`

```yaral
rule cloudfox_aws_multi_service_enumeration_fanout_console_excluded {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "CF-A04"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.product_name = "AWS CloudTrail"
    re.regex($e.metadata.product_event_type, `^(List|Describe|Get)[A-Z]`)
    $e.additional.fields["session_credential_from_console"] != "true"
    $e.principal.user.userid = $principal
    $e.target.application = $service
  match:
    $principal over 10s
  outcome:
    $services = count_distinct($service)
  condition:
    $e and $services >= 10
}
```

## Re-comparison against revised canonical rule

- The adopted rule was re-run against the branch matrix above on 2026-11-21. It closes the targeted branch within declared telemetry; the residual limits are in `reviews/cloudfox/detection-review.md`.
- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule cloudfox_aws_multi_service_enumeration_fanout {
  meta:
    author = "Detection Research Agent"
    description = "Detects one AWS principal issuing List, Describe or Get calls to fifteen or more distinct AWS services within 30 minutes, the breadth signature of automated account enumeration."
    date = "2026-11-21"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "Automated recon tools sweep many services quickly; humans and most single-purpose automation touch few. Breadth is tool-agnostic, but cloud-management and posture platforms overlap."
    procedure_ids = "CF-A01,CF-A02,CF-A04,CF-A06"
    log_source_prerequisites = "AWS CloudTrail management events normalized with metadata.product_name = 'AWS CloudTrail', eventName in metadata.product_event_type, eventSource in target.application, userIdentity ARN in principal.user.userid; read-only management events enabled on the trail; userAgent in network.http.user_agent (console sessions excluded, CF-DR-09)."
    false_positives = "CSPM, inventory, backup and cloud-governance platforms; approved security assessments. Approve their role ARNs."
    references = "reports/cloudfox/source-analysis.md#procedure-analysis; reviews/cloudfox/detection-review.md; public-rules/comparisons/cloudfox/cloudfox_aws_multi_service_enumeration_fanout.md; reviews/cloudfox/detection-review.md#cf-dr-09"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized CloudTrail read events from one ARN across 15 services in 30 minutes and baseline CSPM roles."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/cloudfox/detection-review.md"
  events:
    $e.metadata.product_name = "AWS CloudTrail"
    re.regex($e.metadata.product_event_type, `^(List|Describe|Get)[A-Z]`)
    not re.regex($e.network.http.user_agent, `(?i)(console\.amazonaws\.com|signin\.amazonaws\.com|AWS Internal)`)
    $e.principal.user.userid = $principal
    $e.target.application = $service
  match:
    $principal over 30m
  outcome:
    $services = count_distinct($service)
    $source_ips = array_distinct($e.principal.ip)
    $user_agents = array_distinct($e.network.http.user_agent)
  condition:
    $e and $services >= 15
}
```
