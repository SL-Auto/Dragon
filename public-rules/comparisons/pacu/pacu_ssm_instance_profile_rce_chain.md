# Public-rule comparison: pacu_ssm_instance_profile_rce_chain

## Identity and independence gate

- Internal tool: `pacu` (revision `7dd34aa0856b2a964763a70be9dc9d78abc08a81`)
- Internal canonical rule: `detections/pacu/yaral/pacu_ssm_instance_profile_rce_chain.yaral`
- Internal SHA-256: `c2bce664bddb95571af6054fbf4f2ea03dcbe83696ab12a58bc69375b258e854`
- Internal review completed before public comparison: `yes` (`reviews/pacu/detection-review.md`, PA-DR-01 to PA-DR-08)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/aws/execution_ssm_sendcommand_by_rare_user.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/aws/execution_ssm_sendcommand_by_rare_user.toml) - SHA-256 `2b0865634d7e9acb92029ae360524492b3533192f9fba2fbadd3c2dc11c4529a`
- Scope mapping rationale: Both detect SSM SendCommand used for execution (T1651). The public rule flags SendCommand by a principal not seen before; ours requires a preceding instance-profile association by the same principal.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Instance profile attached, then SendCommand | covered | covered when the principal is new | association plus command - strong | none | ours_stronger |
| SendCommand alone by a new principal | not covered | covered (new terms) | novelty - moderate | none | public_stronger |

## Missing detection branches

- SendCommand without a preceding profile change by a known principal.

## Detection edge cases and blind spots

- Novelty needs a history baseline.

## Signal-quality assessment

- Ours: two-step chain - strong.
- Public: new-terms novelty - moderate.

## Public-rule weaknesses

- Relies on history, not behavior.

## Internal-rule weaknesses

- Misses SendCommand-only execution.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/pacu/source-analysis.md`, `telemetry/pacu.md` and `reviews/pacu/detection-review.md`.
- Decision: `reject`.
- Reason: the proposal is not adopted:
  - The proposal is a single-event SendCommand-by-new-principal rule. YARA-L has no native new-terms baseline, and without one the rule fires on every SendCommand. The chain rule plus SSM command history in triage cover Pacu's `systemsmanager__rce_ec2`, which always attaches a profile first.
- Canonical result: no canonical logic changed; the proposed code is preserved below.
- Regeneration: none required; canonical logic is unchanged.

## Unmatched scope

None. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `new_rule`
- Addresses branches: SendCommand by a first-seen principal.
- Required telemetry: CloudTrail SendCommand with baseline.
- Validation status: `unvalidated_proposal`

```yaral
rule pacu_ssm_sendcommand_any {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PA-P09"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.product_event_type = "SendCommand"
    $e.principal.user.userid = $principal
  match:
    $principal over 1h
  condition:
    $e
}
```
