# Public-rule comparison: cobalt_strike_powershell_or_clr_in_unusual_host

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_powershell_or_clr_in_unusual_host.yaral`
- Internal SHA-256: `f71d27760edbdf9e66752e21ce05e9640727f28252cec917b8d57249b6ac1962`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-015,CSB-017`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/chronicle-community/234e9223c3b8f3d1c30209d9663797ba69057533/rules-community/microsoft/windows/base64_encoded_powershell_command_detected.yaral`](../../snapshots/chronicle-community/234e9223c3b8f3d1c30209d9663797ba69057533/rules-community/microsoft/windows/base64_encoded_powershell_command_detected.yaral) - SHA-256 `9d5911d5aa2803b1ee3765ac1e2ba7c3a84591b6473b3a6c6d7d97aeadf25529`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite and execution context | Process/entity context is retained | Candidate supplies a narrower implementation-specific context | Process attribution - moderate | identity/session baseline | complementary | Canonical rule and pinned candidate above. |
| PowerShell or CLR runtime hosted in an unusual process | runtime/script telemetry keyed to unusual host identity | PowerShell rules add script-content and encoded/download branches, while CLR rules add module-load ancestry | runtime initialization in rare unsigned process - strong | ordered downstream security effect | complementary | Procedure `CSB-015,CSB-017` and the cited public rule cover overlapping but non-identical observables. |
| Resulting security effect or artifact | Partially covered | Partially covered | result correlation - strong when present | host/user/time-bounded sequence | different_scope | Neither rule proves every procedure outcome. |

## Missing detection branches

- Missing from ours: CLR initialization in unsigned network-facing processes and PowerShell without script-block telemetry.
- Missing from the public candidate: the complete tool-independent ordered procedure and all Beacon-supported implementation variants.
- Missing from both: reliable attribution to Cobalt Strike; these are behavioral detections and must not claim tool identity.

## Detection edge cases and blind spots

legitimate automation embeds CLR or PowerShell; runtime telemetry can be absent. Partial collection, clock skew, event loss, and process or identity key reuse can also break correlations. Low-and-slow activity may fall outside fixed windows, while distributing steps across processes can defeat same-process joins. These are detection limitations, not operational guidance.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| runtime initialization in rare unsigned process | strong | ours | Close to the relevant security effect and less dependent on mutable names. | Depends on normalized process/entity fields and local baselines. |
| Candidate implementation indicator | moderate | public | Adds a concrete observable branch absent from ours. | Often tied to one implementation, field model, or default. |
| Name, path, or command fragment alone | weak | public where present | Useful only as context, not proof of the procedure. | Mutable and commonly overlaps administration. |

## Public-rule weaknesses

The candidate is useful as an independent compensating branch, but its narrower implementation assumptions do not cover the complete procedure. Any literal names, paths, command fragments, fixed thresholds, or product enrichments remain fragile until validated locally. It must not be copied blindly.

## Internal-rule weaknesses

The canonical rule has broader tool-independent intent, but CLR initialization in unsigned network-facing processes and PowerShell without script-block telemetry. Its correlation also assumes consistent entity normalization and adequate collection across the declared window.

## Decision trail

- Candidate improvement: independently add the branch below, using public coverage only as evidence that the observable is useful.
- Independent verification: required against the Cobalt Strike procedure report, provider semantics, local schema mappings, and sanitized authorized telemetry.
- Decision: `deferred_pending_rule_improvement_run`
- Reason: `The proposal is detection-engineering input, not accepted canonical logic.`
- Required regeneration: `canonical adversarial review, coverage, telemetry and master counts, all five translations, dependencies/manifests/hashes, and this comparison.`

## Unmatched scope

The public candidate does not cover all branches in `CSB-015,CSB-017`. Conversely, the canonical rule is not evidence of Cobalt Strike attribution and may detect other tooling with equivalent effects.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: CLR initialization in unsigned network-facing processes and PowerShell without script-block telemetry.
- Required telemetry: normalized `MODULE_LOAD` plus the entity, enrichment, and correlation fields used below; collection health must be monitored.
- Validation status: `unvalidated_proposal`

```yaral
rule cobalt_strike_powershell_or_clr_in_unusual_host_compensating_signal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    description = "Independent compensating signal proposed after public-rule comparison"
    procedure_ids = "CSB-015,CSB-017"
  events:
    $e.metadata.event_type = "MODULE_LOAD"
        $e.principal.process.file.sha256 = $process_hash
        re.regex($e.target.file.full_path, `(?i)\\(clr|coreclr)\.dll$`)
        $e.additional.fields["process_signed"].value.bool_value = false
        $e.additional.fields["process_prevalence"].value.string_value = "RARE"
  match:
    $process_hash over 10m
  condition:
    $e
}
```

This proposal is deliberately not canonical. Thresholds, field availability, benign prevalence, and join stability require adversarial review. Remaining gaps include telemetry loss, cross-host clock skew, and variants that do not produce the proposed effect.

If accepted or modified, update the canonical rule in the same run and regenerate every required downstream artifact before marking the comparison complete.
