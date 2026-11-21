# Public-rule comparison: pacu_detection_service_impairment

## Identity and independence gate

- Internal tool: `pacu` (revision `7dd34aa0856b2a964763a70be9dc9d78abc08a81`)
- Internal canonical rule: `detections/pacu/yaral/pacu_detection_service_impairment.yaral`
- Internal SHA-256: `6609a6209fb2c90a297e7d6ca432d586578a634eb22e7538e73f5f6c7d026e08`
- Internal review completed before public comparison: `yes` (`reviews/pacu/detection-review.md`, PA-DR-01 to PA-DR-08)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/aws/defense_evasion_cloudtrail_logging_suspended.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/aws/defense_evasion_cloudtrail_logging_suspended.toml) - SHA-256 `1d43f8a4c2840c27a0c266519c6aa3b1819e9b6e7eaafe4c48cff7cb5f166bb1`
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/aws/defense_evasion_guardduty_detector_deletion.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/aws/defense_evasion_guardduty_detector_deletion.toml) - SHA-256 `9c743f4f24f6c2550c4ace466852c556454c2b546833f976a2dfeccfa7376692`
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/aws/defense_evasion_guardduty_finding_suppression.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/aws/defense_evasion_guardduty_finding_suppression.toml) - SHA-256 `09ced8290692e71960c236acc2febcca82a000ff7eb2de79e686621e45fbf5fb`
- Scope mapping rationale: All detect impairment of AWS monitoring (T1562.008). Elastic splits CloudTrail suspension, GuardDuty detector deletion and GuardDuty finding suppression into separate rules.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| CloudTrail StopLogging or DeleteTrail | covered | covered | management event - strong | none | equivalent |
| GuardDuty detector deleted or disabled | covered | covered (deletion) | management event - strong | none | equivalent |
| GuardDuty trusted IP set created or updated | covered | not covered | CreateIPSet/UpdateIPSet - strong | none | ours_stronger |
| GuardDuty findings suppressed with a filter | not covered (Pacu does not create filters) | covered | CreateFilter archive - strong | none | different_scope |
| Config, flow-log and alarm impairment | covered | not covered by these candidates | management event - strong | none | ours_stronger |

## Missing detection branches

- GuardDuty finding filters are outside Pacu's source.

## Detection edge cases and blind spots

- Dual-use UpdateTrail and UpdateDetector (PA-DR-07).

## Signal-quality assessment

- All: management events close to the effect - strong.

## Public-rule weaknesses

- They are split across rules and do not cover Config, flow logs or alarms.

## Internal-rule weaknesses

- UpdateTrail and UpdateDetector overlap with benign changes.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/pacu/source-analysis.md`, `telemetry/pacu.md` and `reviews/pacu/detection-review.md`.
- Decision: `reject`.
- Reason: the proposal is not adopted:
  - The proposal would add GuardDuty `CreateFilter` with an archive action. `detection__disruption` and `guardduty__whitelist_ip` never call it, so it adds a procedure Pacu does not perform.
- Canonical result: no canonical logic changed; the proposed code is preserved below.
- Regeneration: none required; canonical logic is unchanged.

## Unmatched scope

GuardDuty filter suppression belongs to tools that call CreateFilter. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: GuardDuty finding suppression filters.
- Required telemetry: CloudTrail GuardDuty management events.
- Validation status: `unvalidated_proposal`

```yaral
rule pacu_guardduty_filter_suppression {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PA-P07"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.product_event_type = "CreateFilter"
    re.regex($e.additional.fields["action"], `(?i)ARCHIVE`)
  condition:
    $e
}
```
