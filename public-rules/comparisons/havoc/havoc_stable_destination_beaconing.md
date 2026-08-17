# Public-rule comparison: havoc_stable_destination_beaconing

## Identity and independence gate

- Internal rule: `detections/havoc/yaral/havoc_stable_destination_beaconing.yaral`
- Internal SHA-256: `58a6ab176f8832e2d1bcb6399831881709e35d4f92ffc9cc896f3a9d5b27d22b`
- Internal review completed before public comparison: `true`
- Procedures: HV-P01, HV-P03
- Public candidates were consulted only after independent source analysis, rule generation and adversarial review.

- [`public-rules/snapshots/microsoft-sentinel/5f947544657288586559c41b218eaaf182636728/Detections/ASimNetworkSession/PossibleBeaconingActivity.yaml`](../../snapshots/microsoft-sentinel/5f947544657288586559c41b218eaaf182636728/Detections/ASimNetworkSession/PossibleBeaconingActivity.yaml) - SHA-256 `3734a32db60c4407ee333c5c55c14ed635237cef4e4ac2f338064b59ac399e93`

## Procedure and detection-branch matrix

| Branch | Our rule | Public rule | Primary signal and strength | Gap |
| --- | --- | --- | --- | --- |
| Preconditions and context | process/entity context | source-specific context | moderate â€” establishes causal scope | Both depend on source completeness |
| Security-sensitive action | process and destination recurrence with active-minute threshold | destination-aware flow recurrence | strong when close to the effect; weak when name/default based | collection-health and prevalence context |
| Resulting effect | correlated endpoint/network effect | candidate-specific effect | moderate to strong depending parser fidelity | Missing entity fields break joins |
| Cleanup or low-and-slow | partial | partial or absent | weak â€” neither proves completeness | Distributed, sparse and delayed behavior remains difficult |

## Missing detection branches

- Primary missing or weak branch: collection-health and prevalence context.
- Neither rule can compensate for absent collection or unbounded extension behavior.
- Tool attribution is not inferred from shared behavior.

## Detection edge cases and blind spots

- Stable process identity can be lost through PID reuse, parser mismatch or sensor restart.
- Low-volume, distributed and delayed activity may fall outside the correlation window or threshold.
- Vendor semantic events require tenant verification; configurable names and infrastructure are not reliable gates.
- Benign administration, monitoring and security products can produce overlapping effects.

## Signal-quality assessment

- Our primary signal: process and destination recurrence with active-minute threshold; `moderate` to `strong` because it correlates behavior/effect but remains telemetry-dependent.
- Public primary signal: destination-aware flow recurrence; strength varies with proximity to the effect and reliance on mutable implementation details.
- Scoped conclusion: `complementary` for the listed procedures only.

## Public-rule weaknesses

- The candidate is narrower, implementation-specific, product-specific, or absent for some Havoc branches.
- Public exclusions, thresholds and data-model assumptions are not trusted without independent validation.

## Internal-rule weaknesses

- collection-health and prevalence context.
- Canonical joins and thresholds remain experimental pending representative tenant fixtures.

## Decision trail

- Candidate improvement: collection-health and prevalence context
- Independent verification: pinned Havoc report, internal review, telemetry contract and candidate hash/path above
- Decision: `rejected`
- Reason: Adversarial review of the proposal (2026-08-16) found it degenerate. The two declared event variables (`$a`, `$b`) have byte-for-byte identical constraints (`metadata.product_event_type = "NETWORK_CONNECTION"`, same `$host`, same `$pid`) with no distinguishing field, so the rule implements no "collection-health and prevalence context" logic at all -- it is a trivial self-referential pair with `condition: $a and $b`, which any single matching connection event can satisfy. Even the proposal's own "Required telemetry" line repeats "concrete NETWORK_CONNECTION and NETWORK_CONNECTION mappings," confirming the text was not adapted from the shared template for this specific branch. It also uses `metadata.product_event_type` rather than this repository's `metadata.event_type` convention.
- Adversarial re-check: Re-ran the procedure-branch matrix against the proposal. It does not close the stated missing branch (collection-health/prevalence context remains open) and adds no enforceable logic beyond the existing canonical `havoc_stable_destination_beaconing` rule; canonical logic is unchanged and no compensating rule is added.
- Required regeneration: none. Canonical logic, telemetry, translations, and dependencies are unchanged because the proposal was rejected, not adopted or modified.

## Unmatched scope

- Public logic does not bound Havoc external services, in-memory job state or unavailable victim/server telemetry.
- Our logic does not inherit candidate-specific allowlists, ML models or command-name coverage.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: collection-health and prevalence context
- Required telemetry: concrete NETWORK_CONNECTION and NETWORK_CONNECTION mappings with stable entity fields and collection health
- Validation status: `unvalidated_proposal`

```yaral
rule havoc_stable_destination_beaconing_proposal {
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