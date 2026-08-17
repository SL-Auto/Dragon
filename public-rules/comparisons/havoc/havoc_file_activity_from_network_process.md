# Public-rule comparison: havoc_file_activity_from_network_process

## Identity and independence gate

- Internal rule: `detections/havoc/yaral/havoc_file_activity_from_network_process.yaral`
- Internal SHA-256: `ad641045eb768c3981522af3392a313c1e526c3119e42901ca1df99b77e84c9d`
- Internal review completed before public comparison: `true`
- Procedures: HV-P06, HV-P07, HV-P08
- Public candidates were consulted only after independent source analysis, rule generation and adversarial review.

- No credible public counterpart found after procedure/effect search; adjacent rules were rejected as insufficient evidence.

## Procedure and detection-branch matrix

| Branch | Our rule | Public rule | Primary signal and strength | Gap |
| --- | --- | --- | --- | --- |
| Preconditions and context | process/entity context | source-specific context | moderate â€” establishes causal scope | Both depend on source completeness |
| Security-sensitive action | same-process file lifecycle and egress | no credible same-procedure public counterpart | strong when close to the effect; weak when name/default based | sensitive read versus staging and deletion |
| Resulting effect | correlated endpoint/network effect | candidate-specific effect | moderate to strong depending parser fidelity | Missing entity fields break joins |
| Cleanup or low-and-slow | partial | partial or absent | weak â€” neither proves completeness | Distributed, sparse and delayed behavior remains difficult |

## Missing detection branches

- Primary missing or weak branch: sensitive read versus staging and deletion.
- Neither rule can compensate for absent collection or unbounded extension behavior.
- Tool attribution is not inferred from shared behavior.

## Detection edge cases and blind spots

- Stable process identity can be lost through PID reuse, parser mismatch or sensor restart.
- Low-volume, distributed and delayed activity may fall outside the correlation window or threshold.
- Vendor semantic events require tenant verification; configurable names and infrastructure are not reliable gates.
- Benign administration, monitoring and security products can produce overlapping effects.

## Signal-quality assessment

- Our primary signal: same-process file lifecycle and egress; `moderate` to `strong` because it correlates behavior/effect but remains telemetry-dependent.
- Public primary signal: no credible same-procedure public counterpart; strength varies with proximity to the effect and reliance on mutable implementation details.
- Scoped conclusion: `insufficient_evidence` for the listed procedures only.

## Public-rule weaknesses

- The candidate is narrower, implementation-specific, product-specific, or absent for some Havoc branches.
- Public exclusions, thresholds and data-model assumptions are not trusted without independent validation.

## Internal-rule weaknesses

- sensitive read versus staging and deletion.
- Canonical joins and thresholds remain experimental pending representative tenant fixtures.

## Decision trail

- Candidate improvement: sensitive read versus staging and deletion
- Independent verification: pinned Havoc report, internal review, telemetry contract and candidate hash/path above
- Decision: `rejected`
- Reason: Adversarial review of the proposal (2026-08-16) found two independent defects. First, it queries `metadata.product_event_type = "FILE_READ"` / `"NETWORK_CONNECTION"`, but every canonical Havoc rule in this repository correctly uses `metadata.event_type` for normalized UDM category values; `product_event_type` holds the raw vendor-specific event identifier, not a semantic UDM enum name, so as written this predicate would not match real telemetry and the rule would silently never fire. Second, independent of the field-name defect, the logic does not implement the branch it claims to address: it correlates a generic FILE_READ with a NETWORK_CONNECTION on the same process with no sensitive-path, staging-directory, or deletion predicate, so it does not distinguish "sensitive read versus staging and deletion" as claimed and duplicates the existing canonical file-lifecycle-plus-egress correlation without adding a new branch.
- Adversarial re-check: Re-ran the procedure-branch matrix against the proposal. It does not close the stated missing branch and is redundant with existing canonical coverage; canonical logic is unchanged and no compensating rule is added.
- Required regeneration: none. Canonical logic, telemetry, translations, and dependencies are unchanged because the proposal was rejected, not adopted or modified.

## Unmatched scope

- Public logic does not bound Havoc external services, in-memory job state or unavailable victim/server telemetry.
- Our logic does not inherit candidate-specific allowlists, ML models or command-name coverage.

## Proposed YARA-L improvement

- Change type: `split`
- Addresses branches: sensitive read versus staging and deletion
- Required telemetry: concrete FILE_READ and NETWORK_CONNECTION mappings with stable entity fields and collection health
- Validation status: `unvalidated_proposal`

```yaral
rule havoc_file_activity_from_network_process_proposal {
  meta:
    status = "experimental"
    validation_status = "unvalidated_proposal"
  events:
    $a.metadata.product_event_type = "FILE_READ"
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