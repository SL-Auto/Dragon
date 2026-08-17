# Public-rule comparison: havoc_recurrent_process_egress

## Identity and independence gate

- Internal rule: `detections/havoc/yaral/havoc_recurrent_process_egress.yaral`
- Internal SHA-256: `3940ecdc051be03fa38cd9143e8eebfa35d3a34b896a13b93e4925606a809fc0`
- Internal review completed before public comparison: `true`
- Procedures: HV-P01, HV-P03
- Public candidates were consulted only after independent source analysis, rule generation and adversarial review.

- [`public-rules/snapshots/microsoft-sentinel/5f947544657288586559c41b218eaaf182636728/Detections/ASimNetworkSession/PossibleBeaconingActivity.yaml`](../../snapshots/microsoft-sentinel/5f947544657288586559c41b218eaaf182636728/Detections/ASimNetworkSession/PossibleBeaconingActivity.yaml) - SHA-256 `3734a32db60c4407ee333c5c55c14ed635237cef4e4ac2f338064b59ac399e93`

## Procedure and detection-branch matrix

| Branch | Our rule | Public rule | Primary signal and strength | Gap |
| --- | --- | --- | --- | --- |
| Preconditions and context | process/entity context | source-specific context | moderate â€” establishes causal scope | Both depend on source completeness |
| Security-sensitive action | process-aware recurrence across destination changes | destination-aware flow recurrence | strong when close to the effect; weak when name/default based | stable-destination recurrence |
| Resulting effect | correlated endpoint/network effect | candidate-specific effect | moderate to strong depending parser fidelity | Missing entity fields break joins |
| Cleanup or low-and-slow | partial | partial or absent | weak â€” neither proves completeness | Distributed, sparse and delayed behavior remains difficult |

## Missing detection branches

- Primary missing or weak branch: stable-destination recurrence.
- Neither rule can compensate for absent collection or unbounded extension behavior.
- Tool attribution is not inferred from shared behavior.

## Detection edge cases and blind spots

- Stable process identity can be lost through PID reuse, parser mismatch or sensor restart.
- Low-volume, distributed and delayed activity may fall outside the correlation window or threshold.
- Vendor semantic events require tenant verification; configurable names and infrastructure are not reliable gates.
- Benign administration, monitoring and security products can produce overlapping effects.

## Signal-quality assessment

- Our primary signal: process-aware recurrence across destination changes; `moderate` to `strong` because it correlates behavior/effect but remains telemetry-dependent.
- Public primary signal: destination-aware flow recurrence; strength varies with proximity to the effect and reliance on mutable implementation details.
- Scoped conclusion: `complementary` for the listed procedures only.

## Public-rule weaknesses

- The candidate is narrower, implementation-specific, product-specific, or absent for some Havoc branches.
- Public exclusions, thresholds and data-model assumptions are not trusted without independent validation.

## Internal-rule weaknesses

- stable-destination recurrence.
- Canonical joins and thresholds remain experimental pending representative tenant fixtures.

## Decision trail

- Candidate improvement: stable-destination recurrence
- Independent verification: pinned Havoc report, internal review, telemetry contract and candidate hash/path above
- Decision: `adopted`
- Reason: Independently verified destination grouping reduces accidental aggregation; implemented as havoc_stable_destination_beaconing without copying the public predicate.
- Required regeneration: canonical review, telemetry, translations, dependencies and comparison when adopted

## Unmatched scope

- Public logic does not bound Havoc external services, in-memory job state or unavailable victim/server telemetry.
- Our logic does not inherit candidate-specific allowlists, ML models or command-name coverage.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: stable-destination recurrence
- Required telemetry: concrete NETWORK_CONNECTION and NETWORK_CONNECTION mappings with stable entity fields and collection health
- Validation status: `unvalidated_proposal`

```yaral
rule havoc_recurrent_process_egress_proposal {
  meta:
    status = "experimental"
    validation_status = "unvalidated_proposal"
  events:
    $a.metadata.product_event_type = "NETWORK_CONNECTION"
    $a.principal.hostname = $host
    $a.principal.process.product_specific_process_id = $pid
    $b.metadata.product_event_type = "NETWORK_CONNECTION"
    $b.principal.hostname = $host
    $b.principal.process.product_specific_process_id = $pid
  match:
    $host, $pid over 10m
  condition:
    $a and $b
}
```

This proposal is actual detection logic for the scoped missing branch, not an automatic adoption. It must be compiled, mapped, benign-baselined and adversarially reviewed before canonical use. The only accepted comparison change in this pass is the independently implemented stable-destination recurrence rule documented above.