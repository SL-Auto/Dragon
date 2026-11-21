# Public-rule comparison: havoc_listener_and_forwarding

## Identity and independence gate

- Internal rule: `detections/havoc/yaral/havoc_listener_and_forwarding.yaral`
- Internal SHA-256: `4473caf91fece20f52071a7ee5c408ee310c53a935be05f2c3f5f8377c604942`
- Internal review completed before public comparison: `true`
- Procedures: HV-P16
- Public candidates were consulted only after independent source analysis, rule generation and adversarial review.

- [`public-rules/snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/port_proxy_forwarding_T1090_cisa_report.yaral`](../../snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/port_proxy_forwarding_T1090_cisa_report.yaral) - SHA-256 `65d283ba8edead9233016571a5ec70310679d7ea31689016379b1283eb42d522`

## Procedure and detection-branch matrix

| Branch | Our rule | Public rule | Primary signal and strength | Gap |
| --- | --- | --- | --- | --- |
| Preconditions and context | process/entity context | source-specific context | moderate â€” establishes causal scope | Both depend on source completeness |
| Security-sensitive action | same-process listen and outbound relay effect | configured Windows port-proxy state | strong when close to the effect; weak when name/default based | host configuration forwarding branch |
| Resulting effect | correlated endpoint/network effect | candidate-specific effect | moderate to strong depending parser fidelity | Missing entity fields break joins |
| Cleanup or low-and-slow | partial | partial or absent | weak â€” neither proves completeness | Distributed, sparse and delayed behavior remains difficult |

## Missing detection branches

- Primary missing or weak branch: host configuration forwarding branch.
- Neither rule can compensate for absent collection or unbounded extension behavior.
- Tool attribution is not inferred from shared behavior.

## Detection edge cases and blind spots

- Stable process identity can be lost through PID reuse, parser mismatch or sensor restart.
- Low-volume, distributed and delayed activity may fall outside the correlation window or threshold.
- Vendor semantic events require tenant verification; configurable names and infrastructure are not reliable gates.
- Benign administration, monitoring and security products can produce overlapping effects.

## Signal-quality assessment

- Our primary signal: same-process listen and outbound relay effect; `moderate` to `strong` because it correlates behavior/effect but remains telemetry-dependent.
- Public primary signal: configured Windows port-proxy state; strength varies with proximity to the effect and reliance on mutable implementation details.
- Scoped conclusion: `complementary` for the listed procedures only.

## Public-rule weaknesses

- The candidate is narrower, implementation-specific, product-specific, or absent for some Havoc branches.
- Public exclusions, thresholds and data-model assumptions are not trusted without independent validation.

## Internal-rule weaknesses

- host configuration forwarding branch.
- Canonical joins and thresholds remain experimental pending representative tenant fixtures.

## Decision trail

- Candidate improvement: host configuration forwarding branch
- Independent verification: pinned Havoc report, internal review, telemetry contract and candidate hash/path above
- Decision: `reject`
- Label normalized (2026-11-21): the earlier token `rejected` is replaced by the contract's terminal value `reject`; the decision and its reasoning are unchanged.
- Reason: Adversarial review of the proposal (2026-08-16) found two independent defects. First, it queries `metadata.product_event_type = "NETWORK_LISTEN"` / `"NETWORK_CONNECTION"`, but every canonical Havoc rule in this repository correctly uses `metadata.event_type` for normalized UDM category values; `product_event_type` holds the raw vendor-specific event identifier, not a semantic UDM enum name, so as written this predicate would not match real telemetry and the rule would silently never fire. Second, independent of the field-name defect, the logic does not implement the branch it claims to address: it correlates NETWORK_LISTEN with NETWORK_CONNECTION on the same process, which is exactly the existing canonical rule's logic, rather than the stated "host configuration forwarding branch" (native OS port-proxy/registry configuration events such as `netsh interface portproxy`), so it adds no new branch and is fully redundant with current coverage.
- Adversarial re-check: Re-ran the procedure-branch matrix against the proposal. It does not close the stated missing branch (host configuration forwarding remains uncovered) and introduces no correlation distinct from the existing canonical rule; canonical logic is unchanged and no compensating rule is added.
- Required regeneration: none. Canonical logic, telemetry, translations, and dependencies are unchanged because the proposal was rejected, not adopted or modified.

## Unmatched scope

- Public logic does not bound Havoc external services, in-memory job state or unavailable victim/server telemetry.
- Our logic does not inherit candidate-specific allowlists, ML models or command-name coverage.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: host configuration forwarding branch
- Required telemetry: concrete NETWORK_LISTEN and NETWORK_CONNECTION mappings with stable entity fields and collection health
- Validation status: `unvalidated_proposal`

```yaral
rule havoc_listener_and_forwarding_proposal {
  meta:
    status = "experimental"
    validation_status = "unvalidated_proposal"
  events:
    $a.metadata.product_event_type = "NETWORK_LISTEN"
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

## Snapshot refresh (2026-11-21)

- Candidate links re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`. The decision trail above is unchanged.
- `rules/community/microsoft/windows/port_proxy_forwarding_T1090_cisa_report.yaral` differs between 234e922 and dbc9beb only in line endings (snapshot path moved where applicable); content is identical.
