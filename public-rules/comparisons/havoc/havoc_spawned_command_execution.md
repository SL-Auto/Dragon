# Public-rule comparison: havoc_spawned_command_execution

## Identity and independence gate

- Internal rule: `detections/havoc/yaral/havoc_spawned_command_execution.yaral`
- Internal SHA-256: `4a237eff5ac3921ab218accbe7de529572d2b679713ca7df325bff547ba1763b`
- Internal review completed before public comparison: `true`
- Procedures: HV-P05
- Public candidates were consulted only after independent source analysis, rule generation and adversarial review.

- [`public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/execution_command_shell_started_by_unusual_process.toml`](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/execution_command_shell_started_by_unusual_process.toml) - SHA-256 `55f3aebbce5d984428cf53d0f2fafa496412640bff7775bec8364b0b32370193`

## Procedure and detection-branch matrix

| Branch | Our rule | Public rule | Primary signal and strength | Gap |
| --- | --- | --- | --- | --- |
| Preconditions and context | process/entity context | source-specific context | moderate â€” establishes causal scope | Both depend on source completeness |
| Security-sensitive action | network-active parent to interpreter child | unusual parent to command shell | strong when close to the effect; weak when name/default based | rare-parent fallback when network attribution is absent |
| Resulting effect | correlated endpoint/network effect | candidate-specific effect | moderate to strong depending parser fidelity | Missing entity fields break joins |
| Cleanup or low-and-slow | partial | partial or absent | weak â€” neither proves completeness | Distributed, sparse and delayed behavior remains difficult |

## Missing detection branches

- Primary missing or weak branch: rare-parent fallback when network attribution is absent.
- Neither rule can compensate for absent collection or unbounded extension behavior.
- Tool attribution is not inferred from shared behavior.

## Detection edge cases and blind spots

- Stable process identity can be lost through PID reuse, parser mismatch or sensor restart.
- Low-volume, distributed and delayed activity may fall outside the correlation window or threshold.
- Vendor semantic events require tenant verification; configurable names and infrastructure are not reliable gates.
- Benign administration, monitoring and security products can produce overlapping effects.

## Signal-quality assessment

- Our primary signal: network-active parent to interpreter child; `moderate` to `strong` because it correlates behavior/effect but remains telemetry-dependent.
- Public primary signal: unusual parent to command shell; strength varies with proximity to the effect and reliance on mutable implementation details.
- Scoped conclusion: `complementary` for the listed procedures only.

## Public-rule weaknesses

- The candidate is narrower, implementation-specific, product-specific, or absent for some Havoc branches.
- Public exclusions, thresholds and data-model assumptions are not trusted without independent validation.

## Internal-rule weaknesses

- rare-parent fallback when network attribution is absent.
- Canonical joins and thresholds remain experimental pending representative tenant fixtures.

## Decision trail

- Candidate improvement: rare-parent fallback when network attribution is absent
- Independent verification: pinned Havoc report, internal review, telemetry contract and candidate hash/path above
- Decision: `rejected`
- Reason: Adversarial review of the proposal (2026-08-16) found the logic self-contradictory in addition to the field-mapping defect. It queries `metadata.product_event_type = "PROCESS_LAUNCH"` / `"NETWORK_CONNECTION"` rather than this repository's established `metadata.event_type` convention, so it would not match real telemetry. More fundamentally, the proposed rule requires a NETWORK_CONNECTION event, which directly contradicts its own stated purpose of being a "rare-parent fallback when network attribution is absent" -- a fallback for missing network telemetry cannot itself require that same network telemetry to fire -- and it adds no parent-process rarity or baseline predicate that would actually implement a rare-parent branch.
- Adversarial re-check: Re-ran the procedure-branch matrix against the proposal. It does not close the stated missing branch and is internally inconsistent with its own premise; canonical logic is unchanged and no compensating rule is added.
- Required regeneration: none. Canonical logic, telemetry, translations, and dependencies are unchanged because the proposal was rejected, not adopted or modified.

## Unmatched scope

- Public logic does not bound Havoc external services, in-memory job state or unavailable victim/server telemetry.
- Our logic does not inherit candidate-specific allowlists, ML models or command-name coverage.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: rare-parent fallback when network attribution is absent
- Required telemetry: concrete PROCESS_LAUNCH and NETWORK_CONNECTION mappings with stable entity fields and collection health
- Validation status: `unvalidated_proposal`

```yaral
rule havoc_spawned_command_execution_proposal {
  meta:
    status = "experimental"
    validation_status = "unvalidated_proposal"
  events:
    $a.metadata.product_event_type = "PROCESS_LAUNCH"
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