# Public-rule comparison: havoc_cleanup_after_network_activity

## Identity and independence gate

- Internal rule: `detections/havoc/yaral/havoc_cleanup_after_network_activity.yaral`
- Internal SHA-256: `0dcdcc6357d0cf099621fefbf9d8e2f214b18ebcc88f0513d12dbabff25bbc50`
- Internal review completed before public comparison: `true`
- Procedures: HV-P20
- Public candidates were consulted only after independent source analysis, rule generation and adversarial review.

- No credible public counterpart found after procedure/effect search; adjacent rules were rejected as insufficient evidence.

## Procedure and detection-branch matrix

| Branch | Our rule | Public rule | Primary signal and strength | Gap |
| --- | --- | --- | --- | --- |
| Preconditions and context | process/entity context | source-specific context | moderate â€” establishes causal scope | Both depend on source completeness |
| Security-sensitive action | same-process deletion or termination after egress | no credible cleanup sequence counterpart | strong when close to the effect; weak when name/default based | helper-process and delayed cleanup |
| Resulting effect | correlated endpoint/network effect | candidate-specific effect | moderate to strong depending parser fidelity | Missing entity fields break joins |
| Cleanup or low-and-slow | partial | partial or absent | weak â€” neither proves completeness | Distributed, sparse and delayed behavior remains difficult |

## Missing detection branches

- Primary missing or weak branch: helper-process and delayed cleanup.
- Neither rule can compensate for absent collection or unbounded extension behavior.
- Tool attribution is not inferred from shared behavior.

## Detection edge cases and blind spots

- Stable process identity can be lost through PID reuse, parser mismatch or sensor restart.
- Low-volume, distributed and delayed activity may fall outside the correlation window or threshold.
- Vendor semantic events require tenant verification; configurable names and infrastructure are not reliable gates.
- Benign administration, monitoring and security products can produce overlapping effects.

## Signal-quality assessment

- Our primary signal: same-process deletion or termination after egress; `moderate` to `strong` because it correlates behavior/effect but remains telemetry-dependent.
- Public primary signal: no credible cleanup sequence counterpart; strength varies with proximity to the effect and reliance on mutable implementation details.
- Scoped conclusion: `insufficient_evidence` for the listed procedures only.

## Public-rule weaknesses

- The candidate is narrower, implementation-specific, product-specific, or absent for some Havoc branches.
- Public exclusions, thresholds and data-model assumptions are not trusted without independent validation.

## Internal-rule weaknesses

- helper-process and delayed cleanup.
- Canonical joins and thresholds remain experimental pending representative tenant fixtures.

## Decision trail

- Candidate improvement: helper-process and delayed cleanup
- Independent verification: pinned Havoc report, internal review, telemetry contract and candidate hash/path above
- Decision: `reject`
- Label normalized (2026-11-21): the earlier token `rejected` is replaced by the contract's terminal value `reject`; the decision and its reasoning are unchanged.
- Reason: Adversarial review of the proposal (2026-08-16) found two independent defects. First, it queries `metadata.product_event_type = "FILE_DELETION"` / `"PROCESS_TERMINATION"`, but every canonical Havoc rule in this repository (e.g. `detections/havoc/yaral/havoc_cleanup_after_network_activity.yaral` itself, `havoc_stable_destination_beaconing.yaral`) correctly uses `metadata.event_type` for these normalized UDM category values; `product_event_type` holds the raw vendor-specific event identifier (a numeric or product-specific code), not a semantic UDM enum name, so as written this predicate would not match real telemetry from any provider and the rule would silently never fire. Second, independent of the field-name defect, the logic does not implement the branch it claims to address: it correlates file deletion with process termination on the same process/PID (`$a` and `$b`) but drops the outbound-network anchor entirely, so it does not model "helper-process and delayed cleanup" (a different process performing cleanup, or cleanup outside a same-process window) and is a weaker, noisier signal than the existing canonical same-process file-or-termination-plus-egress rule it would sit beside.
- Adversarial re-check: Re-ran the procedure-branch matrix against the proposal. It does not close the stated missing branch (helper-process/delayed cleanup remains an accepted gap per `reviews/havoc/detection-review.md` HV-DR-10) and introduces no new enforceable correlation; canonical logic is unchanged and no compensating rule is added.
- Required regeneration: none. Canonical logic, telemetry, translations, and dependencies are unchanged because the proposal was rejected, not adopted or modified.

## Unmatched scope

- Public logic does not bound Havoc external services, in-memory job state or unavailable victim/server telemetry.
- Our logic does not inherit candidate-specific allowlists, ML models or command-name coverage.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: helper-process and delayed cleanup
- Required telemetry: concrete FILE_DELETION and PROCESS_TERMINATION mappings with stable entity fields and collection health
- Validation status: `unvalidated_proposal`

```yaral
rule havoc_cleanup_after_network_activity_proposal {
  meta:
    status = "experimental"
    validation_status = "unvalidated_proposal"
  events:
    $a.metadata.product_event_type = "FILE_DELETION"
    $a.principal.hostname = $host
    $a.principal.process.product_specific_process_id = $pid
    $b.metadata.product_event_type = "PROCESS_TERMINATION"
    $b.principal.hostname = $host
    $b.principal.process.product_specific_process_id = $pid
  match:
    $host, $pid over 10m
  condition:
    $a and $b
}
```

This proposal is actual detection logic for the scoped missing branch, not an automatic adoption. It must be compiled, mapped, benign-baselined and adversarially reviewed before canonical use. The only accepted comparison change in this pass is the independently implemented stable-destination recurrence rule documented above.