# Public-rule comparison: pacu_snapshot_and_database_takeover

## Identity and independence gate

- Internal tool: `pacu` (revision `7dd34aa0856b2a964763a70be9dc9d78abc08a81`)
- Internal canonical rule: `detections/pacu/yaral/pacu_snapshot_and_database_takeover.yaral`
- Internal SHA-256: `2f37e2c9ddfcc6dcfa3f8cd7451586c37f0a2440e8abaede8b115de4cac8e022`
- Internal review completed before public comparison: `yes` (`reviews/pacu/detection-review.md`, PA-DR-01 to PA-DR-08)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/aws/exfiltration_rds_snapshot_export.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/aws/exfiltration_rds_snapshot_export.toml) - SHA-256 `a1733a49dbf310095597c8d57f53f097283b7c5e7e446550b44a754b1006ffe7`
- Scope mapping rationale: Both target RDS snapshot abuse (T1530). The public rule detects StartExportTask of a snapshot to S3; ours detects snapshot restore, master-password reset and EBS volume attach.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| RDS snapshot restored or master password reset | covered | not covered | restore or password reset - strong | none | ours_stronger |
| RDS snapshot exported to S3 | not covered (Pacu does not export) | covered | StartExportTask - strong | none | different_scope |

## Missing detection branches

- Snapshot export to S3 is outside Pacu's source.

## Detection edge cases and blind spots

- EBS direct data events disabled (PA-DR-01).

## Signal-quality assessment

- Both: management events close to data access - strong.

## Public-rule weaknesses

- Covers only export.

## Internal-rule weaknesses

- Depends on data events for the EBS direct branch.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/pacu/source-analysis.md`, `telemetry/pacu.md` and `reviews/pacu/detection-review.md`.
- Decision: `reject`.
- Reason: the proposal is not adopted:
  - The proposal adds StartExportTask. `rds__explore_snapshots` restores and resets passwords but never exports, so the proposal adds a procedure Pacu does not perform.
- Canonical result: no canonical logic changed; the proposed code is preserved below.
- Regeneration: none required; canonical logic is unchanged.

## Unmatched scope

Snapshot export belongs to tools that call StartExportTask. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: Snapshot export to S3.
- Required telemetry: CloudTrail RDS StartExportTask.
- Validation status: `unvalidated_proposal`

```yaral
rule pacu_rds_snapshot_export {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PA-P10"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.product_event_type = "StartExportTask"
  condition:
    $e
}
```
