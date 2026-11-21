# Public-rule comparison: cobalt_strike_credential_access_effect

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_credential_access_effect.yaral`
- Internal SHA-256: `eeeb5a4c58efefe547cd594ffd9640f1da192b787274e170ab4b5b87f9d70221`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-028`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/potential_credential_dumping_activity_via_lsass.yaral`](../../snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/potential_credential_dumping_activity_via_lsass.yaral) - SHA-256 `7673036c768dbe22209f90cf593685fe9cab3410a7ea3bd4c86679ea2db68522`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite and execution context | Process/entity context is retained | Candidate supplies a narrower implementation-specific context | Process attribution - moderate | identity/session baseline | complementary | Canonical rule and pinned candidate above. |
| credential material access through LSASS, protected stores, or directory replication | effect-oriented LSASS/store/DCSync events independent of utility names | LSASS dump and DCSync rules add concrete access-mask, dump-artifact, and replication branches | dangerous LSASS access followed by dump creation - strong | ordered downstream security effect | complementary | Procedure `CSB-028` and the cited public rule cover overlapping but non-identical observables. |
| Resulting security effect or artifact | Partially covered | Partially covered | result correlation - strong when present | host/user/time-bounded sequence | different_scope | Neither rule proves every procedure outcome. |

## Missing detection branches

- Missing from ours: LSASS access should require dangerous rights or a dump artifact instead of treating every access as equivalent.
- Missing from the public candidate: the complete tool-independent ordered procedure and all Beacon-supported implementation variants.
- Missing from both: reliable attribution to Cobalt Strike; these are behavioral detections and must not claim tool identity.

## Detection edge cases and blind spots

security products vary in PROCESS_OPEN semantics and may omit granted-access detail. Partial collection, clock skew, event loss, and process or identity key reuse can also break correlations. Low-and-slow activity may fall outside fixed windows, while distributing steps across processes can defeat same-process joins. These are detection limitations, not operational guidance.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| dangerous LSASS access followed by dump creation | strong | ours | Close to the relevant security effect and less dependent on mutable names. | Depends on normalized process/entity fields and local baselines. |
| Candidate implementation indicator | moderate | public | Adds a concrete observable branch absent from ours. | Often tied to one implementation, field model, or default. |
| Name, path, or command fragment alone | weak | public where present | Useful only as context, not proof of the procedure. | Mutable and commonly overlaps administration. |

## Public-rule weaknesses

The candidate is useful as an independent compensating branch, but its narrower implementation assumptions do not cover the complete procedure. Any literal names, paths, command fragments, fixed thresholds, or product enrichments remain fragile until validated locally. It must not be copied blindly.

## Internal-rule weaknesses

The canonical rule has broader tool-independent intent, but LSASS access should require dangerous rights or a dump artifact instead of treating every access as equivalent. Its correlation also assumes consistent entity normalization and adequate collection across the declared window.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against source analysis, provider field semantics and `reviews/cobalt-strike-beacon/detection-review.md`.
- Prior state: the proposal was copied into canonical YARA-L on 2026-08-16 while this trail read `deferred_pending_rule_improvement_run`, a non-terminal state the workflow prohibits. It is re-decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real, but adversarial review found defects in the proposal as written; the adopted rule diverges as follows:
  - Added host to both events and the match key; the PID-only key correlated across hosts (DR-14).
  - Enforced first-event-before-second ordering (DR-15).
- Canonical result: `detections/cobalt-strike-beacon/yaral/cobalt_strike_credential_access_effect_compensating_signal.yaral`, SHA-256 `0d55538657e34f0b29d6f7a657deb324de792bf1792e6592f79e9d2d66e3ad00`. The original proposal is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration completed in the same run: detection review, coverage ledger, tool telemetry file, `telemetry/MASTER.md` counts, all five translations, translation review, dependency/manifest hashes, and the re-comparison below.
## Unmatched scope

The public candidate does not cover all branches in `CSB-028`. Conversely, the canonical rule is not evidence of Cobalt Strike attribution and may detect other tooling with equivalent effects.

## Proposed YARA-L improvement

- Change type: `split`
- Addresses branches: LSASS access should require dangerous rights or a dump artifact instead of treating every access as equivalent.
- Required telemetry: normalized `PROCESS_OPEN` plus the entity, enrichment, and correlation fields used below; collection health must be monitored.
- Validation status: `unvalidated_proposal`

```yaral
rule cobalt_strike_credential_access_effect_compensating_signal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    description = "Independent compensating signal proposed after public-rule comparison"
    procedure_ids = "CSB-028"
  events:
    $open.metadata.event_type = "PROCESS_OPEN"
        re.regex($open.target.process.file.full_path, `(?i)\\lsass\.exe$`)
        $open.additional.fields["dangerous_memory_rights"].value.bool_value = true
        $open.principal.process.pid = $pid
        $dump.metadata.event_type = "FILE_CREATION"
        $dump.principal.process.pid = $pid
        re.regex($dump.target.file.full_path, `(?i)\.(dmp|mdmp)$`)
  match:
    $pid over 5m
  condition:
    $open and $dump
}
```

This proposal is deliberately not canonical. Thresholds, field availability, benign prevalence, and join stability require adversarial review. Remaining gaps include telemetry loss, cross-host clock skew, and variants that do not produce the proposed effect.

If accepted or modified, update the canonical rule in the same run and regenerate every required downstream artifact before marking the comparison complete.

## Re-comparison against revised canonical rule

- Revised rule SHA-256 `0d55538657e34f0b29d6f7a657deb324de792bf1792e6592f79e9d2d66e3ad00`, compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/community/microsoft/windows/potential_credential_dumping_activity_via_lsass.yaral` differs from the prior revision only in tag metadata or line endings; its detection logic is unchanged.

| Procedure branch / observable effect | Revised ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| LSASS open with dangerous rights then dump file by same process | covered, same host and process, ordered | `potential_credential_dumping_activity_via_lsass.yaral`: narrower implementation-specific context (original matrix); candidate not re-assessed beyond re-pinning | access-plus-artifact sequence - strong | base credential-effect rule - moderate | complementary | Revised canonical rule, re-pinned candidate, `reviews/cobalt-strike-beacon/detection-review.md`. |

- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule cobalt_strike_credential_access_effect_compensating_signal {
  meta:
    author = "Detection Research Agent"
    description = "Correlates dangerous-rights LSASS process access with creation of a memory-dump artifact by the same process, narrowing the broad LSASS/store/replication effect rule to an ordered access-plus-artifact sequence."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Dangerous-rights LSASS access followed by dump-file creation from the same process is close to the credential-theft security effect, though EDR/forensic tooling can legitimately create similarly named dump artifacts."
    procedure_ids = "CSB-028"
    log_source_prerequisites = "Normalize EDR PROCESS_OPEN against lsass.exe with a granted-access/dangerous-rights enrichment field, plus FILE_CREATION for .dmp/.mdmp targets, joined on host and process ID (stable vendor process ID preferred) within a 5-minute window, open before dump."
    false_positives = "EDR/AV LSASS scanners, Procdump-based support workflows, Windows Error Reporting crash dumps, and forensic acquisition tools that also create .dmp files."
    references = "reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_credential_access_effect.md"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized EDR fixtures pairing benign LSASS access with unrelated dump creation to confirm the join requires both legs; never read real credentials or LSASS memory."
    review_status = "reviewed"
    review_reference = "reviews/cobalt-strike-beacon/detection-review.md"
    compensates_for = "cobalt_strike_credential_access_effect"
    source_comparison = "public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_credential_access_effect.md"
  events:
    $open.metadata.event_type = "PROCESS_OPEN"
    $open.principal.hostname = $host
    re.regex($open.target.process.file.full_path, `(?i)\\lsass\.exe$`)
    $open.additional.fields["dangerous_memory_rights"].value.bool_value = true
    $open.principal.process.product_specific_process_id = $pid
    $dump.metadata.event_type = "FILE_CREATION"
    $dump.principal.hostname = $host
    $dump.principal.process.product_specific_process_id = $pid
    re.regex($dump.target.file.full_path, `(?i)\.(dmp|mdmp)$`)
    $open.metadata.event_timestamp.seconds <= $dump.metadata.event_timestamp.seconds
  match:
    $host, $pid over 5m
  outcome:
    $dump_paths = array_distinct($dump.target.file.full_path)
  condition:
    $open and $dump
}
```

- Re-comparison outcome: the revised rule closes the branch the proposal targeted, within its declared telemetry. Remaining limits are the accepted gaps in `reviews/cobalt-strike-beacon/detection-review.md`, each with a named compensating rule.
