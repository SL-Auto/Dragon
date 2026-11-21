# Public-rule comparison: havoc_memory_execution_from_network_process

## Identity and independence gate

- Internal rule: `detections/havoc/yaral/havoc_memory_execution_from_network_process.yaral`
- Internal SHA-256: `52ba2d0487582d0fc9989406ca88816fab3a1d9bd56a06d1eb0795d6fce6798a`
- Internal review completed before public comparison: `true`
- Procedures: HV-P09, HV-P10, HV-P11
- Public candidates were consulted only after independent source analysis, rule generation and adversarial review.

- [`public-rules/snapshots/splunk-security-content/21509485465aaed2cfa4604e3d2ab5ee52975f0a/detections/endpoint/windows_process_injection_remote_thread.yml`](../../snapshots/splunk-security-content/21509485465aaed2cfa4604e3d2ab5ee52975f0a/detections/endpoint/windows_process_injection_remote_thread.yml) - SHA-256 `be5bef467c0519c5555da8ef410102a1922475d42e985483a42e9c6adf5865b2`

## Procedure and detection-branch matrix

| Branch | Our rule | Public rule | Primary signal and strength | Gap |
| --- | --- | --- | --- | --- |
| Preconditions and context | process/entity context | source-specific context | moderate â€” establishes causal scope | Both depend on source completeness |
| Security-sensitive action | broader verified memory execution plus egress | remote-thread process injection | strong when close to the effect; weak when name/default based | direct cross-process access and execution sequence |
| Resulting effect | correlated endpoint/network effect | candidate-specific effect | moderate to strong depending parser fidelity | Missing entity fields break joins |
| Cleanup or low-and-slow | partial | partial or absent | weak â€” neither proves completeness | Distributed, sparse and delayed behavior remains difficult |

## Missing detection branches

- Primary missing or weak branch: direct cross-process access and execution sequence.
- Neither rule can compensate for absent collection or unbounded extension behavior.
- Tool attribution is not inferred from shared behavior.

## Detection edge cases and blind spots

- Stable process identity can be lost through PID reuse, parser mismatch or sensor restart.
- Low-volume, distributed and delayed activity may fall outside the correlation window or threshold.
- Vendor semantic events require tenant verification; configurable names and infrastructure are not reliable gates.
- Benign administration, monitoring and security products can produce overlapping effects.

## Signal-quality assessment

- Our primary signal: broader verified memory execution plus egress; `moderate` to `strong` because it correlates behavior/effect but remains telemetry-dependent.
- Public primary signal: remote-thread process injection; strength varies with proximity to the effect and reliance on mutable implementation details.
- Scoped conclusion: `complementary` for the listed procedures only.

## Public-rule weaknesses

- The candidate is narrower, implementation-specific, product-specific, or absent for some Havoc branches.
- Public exclusions, thresholds and data-model assumptions are not trusted without independent validation.

## Internal-rule weaknesses

- direct cross-process access and execution sequence.
- Canonical joins and thresholds remain experimental pending representative tenant fixtures.

## Decision trail

- Candidate improvement: direct cross-process access and execution sequence
- Independent verification: pinned Havoc report, internal review, telemetry contract and candidate hash/path above
- Decision: `reject`
- Label normalized (2026-11-21): the earlier token `rejected` is replaced by the contract's terminal value `reject`; the decision and its reasoning are unchanged.
- Reason: Adversarial review of the proposal (2026-08-16) found two independent defects. First, it queries `metadata.product_event_type = "PROCESS_ACCESS"` / `"REMOTE_THREAD"`, but every canonical Havoc rule in this repository correctly uses `metadata.event_type` for normalized UDM category values, so as written this predicate would not match real telemetry and the rule would silently never fire. Second, the proposal does not bind a distinct target process for the PROCESS_ACCESS event (both `$a` and `$b` share only the same `$pid` as principal), so it cannot verify the access is genuinely cross-process, and it reuses the REMOTE_THREAD semantic that this repository's own adversarial review already flagged (`reviews/havoc/detection-review.md` HV-DR-04) as an unverified, vendor-dependent mapping requiring tenant-specific parser confirmation before any use -- reintroducing exactly the unbound semantic branch that review explicitly said not to enable.
- Adversarial re-check: Re-ran the procedure-branch matrix against the proposal. It does not close the stated "direct cross-process access and execution sequence" branch because it never differentiates accessor from target; canonical logic is unchanged and no compensating rule is added.
- Required regeneration: none. Canonical logic, telemetry, translations, and dependencies are unchanged because the proposal was rejected, not adopted or modified.

## Unmatched scope

- Public logic does not bound Havoc external services, in-memory job state or unavailable victim/server telemetry.
- Our logic does not inherit candidate-specific allowlists, ML models or command-name coverage.

## Proposed YARA-L improvement

- Change type: `split`
- Addresses branches: direct cross-process access and execution sequence
- Required telemetry: concrete PROCESS_ACCESS and REMOTE_THREAD mappings with stable entity fields and collection health
- Validation status: `unvalidated_proposal`

```yaral
rule havoc_memory_execution_from_network_process_proposal {
  meta:
    status = "experimental"
    validation_status = "unvalidated_proposal"
  events:
    $a.metadata.product_event_type = "PROCESS_ACCESS"
    $a.principal.hostname = $host
    $a.principal.process.product_specific_process_id = $pid
    $b.metadata.product_event_type = "REMOTE_THREAD"
    $b.principal.hostname = $host
    $b.principal.process.product_specific_process_id = $pid
  match:
    $host, $pid over 10m
  condition:
    $a and $b
}
```

This proposal is actual detection logic for the scoped missing branch, not an automatic adoption. It must be compiled, mapped, benign-baselined and adversarially reviewed before canonical use. The only accepted comparison change in this pass is the independently implemented stable-destination recurrence rule documented above.

## Snapshot refresh (2026-11-21)

- Candidate links re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`. The decision trail above is unchanged.
- `detections/endpoint/windows_process_injection_remote_thread.yml` changed between 457ce9f and 2150948; re-read on 2026-11-21: only modification date and analytic-story metadata changed; the search is identical. The comparison conclusions and decision are unaffected.
