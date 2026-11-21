# Public-rule comparison: scoutsuite_cli_execution

## Identity and independence gate

- Internal tool: `scoutsuite` (revision `7909f2fc6186063e5c9e7ddef8c4d7d1072c8f3d`)
- Internal canonical rule: `detections/scoutsuite/yaral/scoutsuite_cli_execution.yaral`
- Internal SHA-256: `4d847e2620889cb7b0a72d3fada9fdd408d8030bb39cb2ab98fc694fa49d874f`
- Internal review completed before public comparison: `yes` (`reviews/scoutsuite/detection-review.md`, SS-DR-01 to SS-DR-05)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/cross-platform/discovery_cloud_offensive_framework_execution.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/cross-platform/discovery_cloud_offensive_framework_execution.toml) - SHA-256 `93365a0cb2ad19351acd10f7623cee4aa5611f70f313a9f1b7c25c23d45b4df8`
- Scope mapping rationale: Both detect execution of cloud auditing or offensive tooling on an endpoint (T1580). The public rule matches process names including scoutsuite; ours matches ScoutSuite's provider subcommand grammar.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| ScoutSuite launched as scout or scout.py with a provider subcommand | covered (grammar) | covered only if the process is named scoutsuite | command grammar - moderate | cloud user-agent rule - strong | ours_stronger |
| Renamed executable or Python module form | covered | not covered | grammar - moderate | none | ours_stronger |
| Other cloud offensive tools | not targeted | covered | process name - weak | none | different_scope |

## Missing detection branches

- None for ScoutSuite.

## Detection edge cases and blind spots

- The installed entry point is scout, not scoutsuite, so the public name list may miss pip installs.

## Signal-quality assessment

- Ours: grammar - moderate.
- Public: name list - weak.

## Public-rule weaknesses

- Name-based; may miss the scout entry point.

## Internal-rule weaknesses

- Collision with other scout commands is mitigated (SS-DR-05).

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/scoutsuite/source-analysis.md`, `telemetry/scoutsuite.md` and `reviews/scoutsuite/detection-review.md`.
- Decision: `reject`.
- Reason: the proposal is not adopted:
  - The proposal adds a process-name branch for scoutsuite and scout. The grammar rule already matches the scout entry point with a provider subcommand, and a bare name match on scout collides with unrelated tools.
- Canonical result: no canonical logic changed; the proposed code is preserved below.
- Regeneration: none required; canonical logic is unchanged.

## Unmatched scope

The public rule's other tools are outside ScoutSuite. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: Process-name branch.
- Required telemetry: Process creation with image name.
- Validation status: `unvalidated_proposal`

```yaral
rule scoutsuite_process_name {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "SS-P06"
    source_comparison = "unvalidated_proposal"
  events:
    $p.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($p.target.process.file.full_path, `(?i)[\\/](scoutsuite|scout)(\.exe)?$`)
  condition:
    $p
}
```
