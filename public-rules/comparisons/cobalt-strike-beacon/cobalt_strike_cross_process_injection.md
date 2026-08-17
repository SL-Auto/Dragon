# Public-rule comparison: cobalt_strike_cross_process_injection

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_cross_process_injection.yaral`
- Internal SHA-256: `2bcdf7155871ed5de50630725254560998b72cd42c68c34730311dfc791cc79c`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-018,CSB-019`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/_deprecated/defense_evasion_code_injection_conhost.toml`](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/_deprecated/defense_evasion_code_injection_conhost.toml) - SHA-256 `99f8fc3a036931f74f14500b0e145e8befdc3ffb65987ceeea79e0f115367d28`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite and execution context | Process/entity context is retained | Candidate supplies a narrower implementation-specific context | Process attribution - moderate | identity/session baseline | complementary | Canonical rule and pinned candidate above. |
| cross-process handle acquisition followed by executable memory or remote execution | ordered target-PID correlation without relying on a default spawn process | injection rules add call-stack, unsigned-module, and source/target trust context | cross-process open plus executable-memory effect - strong | ordered downstream security effect | complementary | Procedure `CSB-018,CSB-019` and the cited public rule cover overlapping but non-identical observables. |
| Resulting security effect or artifact | Partially covered | Partially covered | result correlation - strong when present | host/user/time-bounded sequence | different_scope | Neither rule proves every procedure outcome. |

## Missing detection branches

- Missing from ours: same-target executable memory without proof that the opener caused the later effect.
- Missing from the public candidate: the complete tool-independent ordered procedure and all Beacon-supported implementation variants.
- Missing from both: reliable attribution to Cobalt Strike; these are behavioral detections and must not claim tool identity.

## Detection edge cases and blind spots

PID reuse and sensor-local identifiers can create false joins; APC/thread-hijack effects may lack REMOTE_THREAD. Partial collection, clock skew, event loss, and process or identity key reuse can also break correlations. Low-and-slow activity may fall outside fixed windows, while distributing steps across processes can defeat same-process joins. These are detection limitations, not operational guidance.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| cross-process open plus executable-memory effect | strong | ours | Close to the relevant security effect and less dependent on mutable names. | Depends on normalized process/entity fields and local baselines. |
| Candidate implementation indicator | moderate | public | Adds a concrete observable branch absent from ours. | Often tied to one implementation, field model, or default. |
| Name, path, or command fragment alone | weak | public where present | Useful only as context, not proof of the procedure. | Mutable and commonly overlaps administration. |

## Public-rule weaknesses

The candidate is useful as an independent compensating branch, but its narrower implementation assumptions do not cover the complete procedure. Any literal names, paths, command fragments, fixed thresholds, or product enrichments remain fragile until validated locally. It must not be copied blindly.

## Internal-rule weaknesses

The canonical rule has broader tool-independent intent, but same-target executable memory without proof that the opener caused the later effect. Its correlation also assumes consistent entity normalization and adequate collection across the declared window.

## Decision trail

- Candidate improvement: independently add the branch below, using public coverage only as evidence that the observable is useful.
- Independent verification: required against the Cobalt Strike procedure report, provider semantics, local schema mappings, and sanitized authorized telemetry.
- Decision: `deferred_pending_rule_improvement_run`
- Reason: `The proposal is detection-engineering input, not accepted canonical logic.`
- Required regeneration: `canonical adversarial review, coverage, telemetry and master counts, all five translations, dependencies/manifests/hashes, and this comparison.`

## Unmatched scope

The public candidate does not cover all branches in `CSB-018,CSB-019`. Conversely, the canonical rule is not evidence of Cobalt Strike attribution and may detect other tooling with equivalent effects.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: same-target executable memory without proof that the opener caused the later effect.
- Required telemetry: normalized `PROCESS_OPEN` plus the entity, enrichment, and correlation fields used below; collection health must be monitored.
- Validation status: `unvalidated_proposal`

```yaral
rule cobalt_strike_cross_process_injection_compensating_signal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    description = "Independent compensating signal proposed after public-rule comparison"
    procedure_ids = "CSB-018,CSB-019"
  events:
    $open.metadata.event_type = "PROCESS_OPEN"
        $open.principal.hostname = $host
        $open.additional.fields["dangerous_memory_rights"].value.bool_value = true
        $open.principal.process.pid = $source_pid
        $open.target.process.pid = $target_pid
        $effect.metadata.event_type = "EXECUTABLE_MEMORY"
        $effect.principal.process.pid = $source_pid
        $effect.target.process.pid = $target_pid
        $effect.additional.fields["memory_is_private"].value.bool_value = true
        $effect.additional.fields["creator_signed"].value.bool_value = false
  match:
    $host, $source_pid, $target_pid over 5m
  condition:
    $open and $effect
}
```

This proposal is deliberately not canonical. Thresholds, field availability, benign prevalence, and join stability require adversarial review. Remaining gaps include telemetry loss, cross-host clock skew, and variants that do not produce the proposed effect.

If accepted or modified, update the canonical rule in the same run and regenerate every required downstream artifact before marking the comparison complete.
