# Public-rule comparison: cobalt_strike_credential_access_effect

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_credential_access_effect.yaral`
- Internal SHA-256: `eeeb5a4c58efefe547cd594ffd9640f1da192b787274e170ab4b5b87f9d70221`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-028`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/chronicle-community/234e9223c3b8f3d1c30209d9663797ba69057533/rules-community/microsoft/windows/potential_credential_dumping_activity_via_lsass.yaral`](../../snapshots/chronicle-community/234e9223c3b8f3d1c30209d9663797ba69057533/rules-community/microsoft/windows/potential_credential_dumping_activity_via_lsass.yaral) - SHA-256 `7673036c768dbe22209f90cf593685fe9cab3410a7ea3bd4c86679ea2db68522`

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

- Candidate improvement: independently add the branch below, using public coverage only as evidence that the observable is useful.
- Independent verification: required against the Cobalt Strike procedure report, provider semantics, local schema mappings, and sanitized authorized telemetry.
- Decision: `deferred_pending_rule_improvement_run`
- Reason: `The proposal is detection-engineering input, not accepted canonical logic.`
- Required regeneration: `canonical adversarial review, coverage, telemetry and master counts, all five translations, dependencies/manifests/hashes, and this comparison.`

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
