# Public-rule comparison: cobalt_strike_file_cleanup_or_timestomp

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_file_cleanup_or_timestomp.yaral`
- Internal SHA-256: `be19fc74fda1d95ee4d18ca9047f04533e13933cbc06f14114573392f2639694`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-026,CSB-034`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/_deprecated/defense_evasion_process_termination_followed_by_deletion.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/_deprecated/defense_evasion_process_termination_followed_by_deletion.toml) - SHA-256 `eab762b96d2f08524ec4dd0d914c3e4acde49967f4bf437a729c8b5e2318caf3`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite and execution context | Process/entity context is retained | Candidate supplies a narrower implementation-specific context | Process attribution - moderate | identity/session baseline | complementary | Canonical rule and pinned candidate above. |
| file deletion, timestamp manipulation, and teardown artifacts | rare/unsigned process deletion or timestamp events | public rules add deletion-after-termination and timestamp-specific sequence context | execution followed by deletion of the same file - strong | ordered downstream security effect | complementary | Procedure `CSB-026,CSB-034` and the cited public rule cover overlapping but non-identical observables. |
| Resulting security effect or artifact | Partially covered | Partially covered | result correlation - strong when present | host/user/time-bounded sequence | different_scope | Neither rule proves every procedure outcome. |

## Missing detection branches

- Missing from ours: deletion of a recently executed or recently created artifact.
- Missing from the public candidate: the complete tool-independent ordered procedure and all Beacon-supported implementation variants.
- Missing from both: reliable attribution to Cobalt Strike; these are behavioral detections and must not claim tool identity.

## Detection edge cases and blind spots

updaters and installers frequently delete their own temporary files. Partial collection, clock skew, event loss, and process or identity key reuse can also break correlations. Low-and-slow activity may fall outside fixed windows, while distributing steps across processes can defeat same-process joins. These are detection limitations, not operational guidance.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| execution followed by deletion of the same file | strong | ours | Close to the relevant security effect and less dependent on mutable names. | Depends on normalized process/entity fields and local baselines. |
| Candidate implementation indicator | moderate | public | Adds a concrete observable branch absent from ours. | Often tied to one implementation, field model, or default. |
| Name, path, or command fragment alone | weak | public where present | Useful only as context, not proof of the procedure. | Mutable and commonly overlaps administration. |

## Public-rule weaknesses

The candidate is useful as an independent compensating branch, but its narrower implementation assumptions do not cover the complete procedure. Any literal names, paths, command fragments, fixed thresholds, or product enrichments remain fragile until validated locally. It must not be copied blindly.

## Internal-rule weaknesses

The canonical rule has broader tool-independent intent, but deletion of a recently executed or recently created artifact. Its correlation also assumes consistent entity normalization and adequate collection across the declared window.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against source analysis, provider field semantics and `reviews/cobalt-strike-beacon/detection-review.md`.
- Prior state: the proposal was copied into canonical YARA-L on 2026-08-16 while this trail read `deferred_pending_rule_improvement_run`, a non-terminal state the workflow prohibits. It is re-decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real, but adversarial review found defects in the proposal as written; the adopted rule diverges as follows:
  - Event type `FILE_DELETE` replaced by inventory `FILE_DELETION` (legacy alias kept) (DR-13).
  - Enforced first-event-before-second ordering (DR-15).
- Canonical result: `detections/cobalt-strike-beacon/yaral/cobalt_strike_file_cleanup_or_timestomp_compensating_signal.yaral`, SHA-256 `61cc3d7b10379489cda96b84599406042a239c4cf489f6e2f54af66047d38d55`. The original proposal is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration completed in the same run: detection review, coverage ledger, tool telemetry file, `telemetry/MASTER.md` counts, all five translations, translation review, dependency/manifest hashes, and the re-comparison below.
## Unmatched scope

The public candidate does not cover all branches in `CSB-026,CSB-034`. Conversely, the canonical rule is not evidence of Cobalt Strike attribution and may detect other tooling with equivalent effects.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: deletion of a recently executed or recently created artifact.
- Required telemetry: normalized `PROCESS_LAUNCH` plus the entity, enrichment, and correlation fields used below; collection health must be monitored.
- Validation status: `unvalidated_proposal`

```yaral
rule cobalt_strike_file_cleanup_or_timestomp_compensating_signal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    description = "Independent compensating signal proposed after public-rule comparison"
    procedure_ids = "CSB-026,CSB-034"
  events:
    $exec.metadata.event_type = "PROCESS_LAUNCH"
        $exec.principal.hostname = $host
        $exec.target.process.file.full_path = $path
        $del.metadata.event_type = "FILE_DELETE"
        $del.principal.hostname = $host
        $del.target.file.full_path = $path
  match:
    $host, $path over 15m
  condition:
    $exec and $del
}
```

This proposal is deliberately not canonical. Thresholds, field availability, benign prevalence, and join stability require adversarial review. Remaining gaps include telemetry loss, cross-host clock skew, and variants that do not produce the proposed effect.

If accepted or modified, update the canonical rule in the same run and regenerate every required downstream artifact before marking the comparison complete.

## Re-comparison against revised canonical rule

- Revised rule SHA-256 `61cc3d7b10379489cda96b84599406042a239c4cf489f6e2f54af66047d38d55`, compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- All public candidates were re-pinned to the refreshed snapshots with no content change in the referenced files.
- The pinned candidate lives under Elastic `_deprecated/` and is a weak comparator for this branch; a stronger public counterpart should be sought when this comparison is next refreshed.

| Procedure branch / observable effect | Revised ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Executed file deleted shortly afterwards by an unsigned or rare process | covered, execute then delete | `defense_evasion_process_termination_followed_by_deletion.toml`: narrower implementation-specific context (original matrix); candidate not re-assessed beyond re-pinning | execute-then-delete same path - moderate | base rarity rule - weak | complementary | Revised canonical rule, re-pinned candidate, `reviews/cobalt-strike-beacon/detection-review.md`. |

- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule cobalt_strike_file_cleanup_or_timestomp_compensating_signal {
  meta:
    author = "Detection Research Agent"
    description = "Correlates execution of a file with deletion of that same file path by an unsigned or rare process shortly afterward, covering self-deleting-artifact cleanup that the base rarity-only rule does not tie to prior execution."
    date = "2026-11-21"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "Execution followed by self-deletion from an unsigned/rare process is a meaningful cleanup signal, but installers and updaters routinely delete their own temporary files; the rarity/signer gate is required to keep benign volume down."
    procedure_ids = "CSB-026,CSB-034"
    log_source_prerequisites = "Normalize PROCESS_LAUNCH and FILE_DELETE with matching full path, host, and process signer/prevalence on the deleting process, joined within 15 minutes."
    false_positives = "Installers, updaters, and self-extracting archives remain a false-positive source when they are unsigned or rare; the signer/prevalence gate narrows but does not eliminate this overlap."
    references = "reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_file_cleanup_or_timestomp.md"
    validation_status = "needs_validation"
    validation_method = "Replay benign execute-then-self-delete fixtures from both signed and unsigned installers to confirm the gate suppresses the signed case."
    review_status = "reviewed"
    review_reference = "reviews/cobalt-strike-beacon/detection-review.md"
    compensates_for = "cobalt_strike_file_cleanup_or_timestomp"
    source_comparison = "public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_file_cleanup_or_timestomp.md"
    modification_note = "Proposal accepted with a required change: added an unsigned/rare-process gate on the deleting process, matching the base rule's convention, because the original proposal had no gating at all and would match nearly every self-deleting installer or updater."
  events:
    $exec.metadata.event_type = "PROCESS_LAUNCH"
    $exec.principal.hostname = $host
    $exec.target.process.file.full_path = $path
    $del.metadata.event_type = /^(FILE_DELETION|FILE_DELETE)$/
    $del.principal.hostname = $host
    $del.target.file.full_path = $path
    ($del.principal.process.file.is_signed = false or $del.principal.process.file.prevalence = "RARE")
    $exec.metadata.event_timestamp.seconds <= $del.metadata.event_timestamp.seconds
  match:
    $host, $path over 15m
  condition:
    $exec and $del
}
```

- Re-comparison outcome: the revised rule closes the branch the proposal targeted, within its declared telemetry. Remaining limits are the accepted gaps in `reviews/cobalt-strike-beacon/detection-review.md`, each with a named compensating rule.
