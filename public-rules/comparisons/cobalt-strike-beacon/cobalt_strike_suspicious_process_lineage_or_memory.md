# Public-rule comparison: cobalt_strike_suspicious_process_lineage_or_memory

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_suspicious_process_lineage_or_memory.yaral`
- Internal SHA-256: `2739595c7cb1ee3f9152d7c9c9aa2a0c1dde413d380aa8e1c0d37f9ebaecbf45`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-004,CSB-014,CSB-016`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/_deprecated/defense_evasion_code_injection_conhost.toml`](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/_deprecated/defense_evasion_code_injection_conhost.toml) - SHA-256 `99f8fc3a036931f74f14500b0e145e8befdc3ffb65987ceeea79e0f115367d28`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite and execution context | Process/entity context is retained | Candidate supplies a narrower implementation-specific context | Process attribution - moderate | identity/session baseline | complementary | Canonical rule and pinned candidate above. |
| parent/creator mismatch, private executable memory, or unusual in-process execution | memory and lineage effects independent of default process names | public rules add call-stack, backing-file, protection-transition, and ancestry context | private RX memory with execution evidence in non-JIT host - strong | ordered downstream security effect | complementary | Procedure `CSB-004,CSB-014,CSB-016` and the cited public rule cover overlapping but non-identical observables. |
| Resulting security effect or artifact | Partially covered | Partially covered | result correlation - strong when present | host/user/time-bounded sequence | different_scope | Neither rule proves every procedure outcome. |

## Missing detection branches

- Missing from ours: private executable region followed by execution/thread start in that region.
- Missing from the public candidate: the complete tool-independent ordered procedure and all Beacon-supported implementation variants.
- Missing from both: reliable attribution to Cobalt Strike; these are behavioral detections and must not claim tool identity.

## Detection edge cases and blind spots

JIT runtimes legitimately allocate private executable pages. Partial collection, clock skew, event loss, and process or identity key reuse can also break correlations. Low-and-slow activity may fall outside fixed windows, while distributing steps across processes can defeat same-process joins. These are detection limitations, not operational guidance.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| private RX memory with execution evidence in non-JIT host | strong | ours | Close to the relevant security effect and less dependent on mutable names. | Depends on normalized process/entity fields and local baselines. |
| Candidate implementation indicator | moderate | public | Adds a concrete observable branch absent from ours. | Often tied to one implementation, field model, or default. |
| Name, path, or command fragment alone | weak | public where present | Useful only as context, not proof of the procedure. | Mutable and commonly overlaps administration. |

## Public-rule weaknesses

The candidate is useful as an independent compensating branch, but its narrower implementation assumptions do not cover the complete procedure. Any literal names, paths, command fragments, fixed thresholds, or product enrichments remain fragile until validated locally. It must not be copied blindly.

## Internal-rule weaknesses

The canonical rule has broader tool-independent intent, but private executable region followed by execution/thread start in that region. Its correlation also assumes consistent entity normalization and adequate collection across the declared window.

## Decision trail

- Candidate improvement: independently add the branch below, using public coverage only as evidence that the observable is useful.
- Independent verification: required against the Cobalt Strike procedure report, provider semantics, local schema mappings, and sanitized authorized telemetry.
- Decision: `deferred_pending_rule_improvement_run`
- Reason: `The proposal is detection-engineering input, not accepted canonical logic.`
- Required regeneration: `canonical adversarial review, coverage, telemetry and master counts, all five translations, dependencies/manifests/hashes, and this comparison.`

## Unmatched scope

The public candidate does not cover all branches in `CSB-004,CSB-014,CSB-016`. Conversely, the canonical rule is not evidence of Cobalt Strike attribution and may detect other tooling with equivalent effects.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: private executable region followed by execution/thread start in that region.
- Required telemetry: normalized `EXECUTABLE_MEMORY` plus the entity, enrichment, and correlation fields used below; collection health must be monitored.
- Validation status: `unvalidated_proposal`

```yaral
rule cobalt_strike_suspicious_process_lineage_or_memory_compensating_signal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    description = "Independent compensating signal proposed after public-rule comparison"
    procedure_ids = "CSB-004,CSB-014,CSB-016"
  events:
    $mem.metadata.event_type = "EXECUTABLE_MEMORY"
        $mem.principal.hostname = $host
        $mem.principal.process.pid = $pid
        $mem.additional.fields["memory_is_private"].value.bool_value = true
        $mem.additional.fields["memory_has_backing_file"].value.bool_value = false
        $thread.metadata.event_type = "THREAD_START"
        $thread.principal.process.pid = $pid
        $thread.additional.fields["start_address_in_private_rx"].value.bool_value = true
        $thread.additional.fields["approved_jit_host"].value.bool_value = false
  match:
    $host, $pid over 5m
  condition:
    $mem and $thread
}
```

This proposal is deliberately not canonical. Thresholds, field availability, benign prevalence, and join stability require adversarial review. Remaining gaps include telemetry loss, cross-host clock skew, and variants that do not produce the proposed effect.

If accepted or modified, update the canonical rule in the same run and regenerate every required downstream artifact before marking the comparison complete.
