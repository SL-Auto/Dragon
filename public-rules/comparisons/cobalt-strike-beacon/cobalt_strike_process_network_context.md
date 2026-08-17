# Public-rule comparison: cobalt_strike_process_network_context

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_process_network_context.yaral`
- Internal SHA-256: `b255f3a0bfc3a3b322da2599c59439e3665f56ee7e027d5d3d57638296eefd6d`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-001,CSB-002,CSB-005`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/microsoft-sentinel/5f947544657288586559c41b218eaaf182636728/Detections/MultipleDataSources/Solorigate-Network-Beacon.yaml`](../../snapshots/microsoft-sentinel/5f947544657288586559c41b218eaaf182636728/Detections/MultipleDataSources/Solorigate-Network-Beacon.yaml) - SHA-256 `34841670a57349b35c89f48e9c46e0a146c6f2472f487ed46c9cba6565e85eea`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite and execution context | Process/entity context is retained | Candidate supplies a narrower implementation-specific context | Process attribution - moderate | identity/session baseline | complementary | Canonical rule and pinned candidate above. |
| repeated outbound HTTP(S) C2 from an uncommon executable | process-attributed repeated egress with rarity/signature context | beaconing rules add timing periodicity, domain rarity, and long-lived sequence analysis | low-variance periodic egress from rare process - strong | ordered downstream security effect | complementary | Procedure `CSB-001,CSB-002,CSB-005` and the cited public rule cover overlapping but non-identical observables. |
| Resulting security effect or artifact | Partially covered | Partially covered | result correlation - strong when present | host/user/time-bounded sequence | different_scope | Neither rule proves every procedure outcome. |

## Missing detection branches

- Missing from ours: regular callback timing and destination novelty are not explicitly measured.
- Missing from the public candidate: the complete tool-independent ordered procedure and all Beacon-supported implementation variants.
- Missing from both: reliable attribution to Cobalt Strike; these are behavioral detections and must not claim tool identity.

## Detection edge cases and blind spots

software updaters and telemetry agents exhibit periodic egress. Partial collection, clock skew, event loss, and process or identity key reuse can also break correlations. Low-and-slow activity may fall outside fixed windows, while distributing steps across processes can defeat same-process joins. These are detection limitations, not operational guidance.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| low-variance periodic egress from rare process | strong | ours | Close to the relevant security effect and less dependent on mutable names. | Depends on normalized process/entity fields and local baselines. |
| Candidate implementation indicator | moderate | public | Adds a concrete observable branch absent from ours. | Often tied to one implementation, field model, or default. |
| Name, path, or command fragment alone | weak | public where present | Useful only as context, not proof of the procedure. | Mutable and commonly overlaps administration. |

## Public-rule weaknesses

The candidate is useful as an independent compensating branch, but its narrower implementation assumptions do not cover the complete procedure. Any literal names, paths, command fragments, fixed thresholds, or product enrichments remain fragile until validated locally. It must not be copied blindly.

## Internal-rule weaknesses

The canonical rule has broader tool-independent intent, but regular callback timing and destination novelty are not explicitly measured. Its correlation also assumes consistent entity normalization and adequate collection across the declared window.

## Decision trail

- Candidate improvement: independently add the branch below, using public coverage only as evidence that the observable is useful.
- Independent verification: required against the Cobalt Strike procedure report, provider semantics, local schema mappings, and sanitized authorized telemetry.
- Decision: `deferred_pending_rule_improvement_run`
- Reason: `The proposal is detection-engineering input, not accepted canonical logic.`
- Required regeneration: `canonical adversarial review, coverage, telemetry and master counts, all five translations, dependencies/manifests/hashes, and this comparison.`

## Unmatched scope

The public candidate does not cover all branches in `CSB-001,CSB-002,CSB-005`. Conversely, the canonical rule is not evidence of Cobalt Strike attribution and may detect other tooling with equivalent effects.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: regular callback timing and destination novelty are not explicitly measured.
- Required telemetry: normalized `NETWORK_CONNECTION` plus the entity, enrichment, and correlation fields used below; collection health must be monitored.
- Validation status: `unvalidated_proposal`

```yaral
rule cobalt_strike_process_network_context_compensating_signal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    description = "Independent compensating signal proposed after public-rule comparison"
    procedure_ids = "CSB-001,CSB-002,CSB-005"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
        $e.principal.process.file.sha256 = $hash
        $e.target.hostname = $domain
        $e.additional.fields["interval_variance_bucket"].value.string_value = "LOW"
        $e.additional.fields["destination_prevalence"].value.string_value = "RARE"
        $e.additional.fields["process_prevalence"].value.string_value = "RARE"
  match:
    $hash, $domain over 2h
  condition:
    $e and #e >= 8
}
```

This proposal is deliberately not canonical. Thresholds, field availability, benign prevalence, and join stability require adversarial review. Remaining gaps include telemetry loss, cross-host clock skew, and variants that do not produce the proposed effect.

If accepted or modified, update the canonical rule in the same run and regenerate every required downstream artifact before marking the comparison complete.
