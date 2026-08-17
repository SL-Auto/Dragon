# Public-rule comparison: havoc_kerberos_ticket_effect

## Identity and independence gate

- Internal rule: `detections/havoc/yaral/havoc_kerberos_ticket_effect.yaral`
- Internal SHA-256: `826d045ddb932ed01ff5697772c836db88dcaaeff8f6fd9a0f87d16bca63eeab`
- Internal review completed before public comparison: `true`
- Procedures: HV-P17
- Public candidates were consulted only after independent source analysis, rule generation and adversarial review.

- [`public-rules/snapshots/splunk-security-content/457ce9f5ea69a8d5be9463989ee23b9366858d16/detections/endpoint/windows_steal_or_forge_kerberos_tickets_klist.yml`](../../snapshots/splunk-security-content/457ce9f5ea69a8d5be9463989ee23b9366858d16/detections/endpoint/windows_steal_or_forge_kerberos_tickets_klist.yml) - SHA-256 `f4a308ecb68264f6f83900e9355254116f7fe669c763fc8e23e8be5d24a71498`

## Procedure and detection-branch matrix

| Branch | Our rule | Public rule | Primary signal and strength | Gap |
| --- | --- | --- | --- | --- |
| Preconditions and context | process/entity context | source-specific context | moderate â€” establishes causal scope | Both depend on source completeness |
| Security-sensitive action | LSA ticket mutation followed by resource use | command-line ticket listing or purge | strong when close to the effect; weak when name/default based | command-line fallback for missing LSA telemetry |
| Resulting effect | correlated endpoint/network effect | candidate-specific effect | moderate to strong depending parser fidelity | Missing entity fields break joins |
| Cleanup or low-and-slow | partial | partial or absent | weak â€” neither proves completeness | Distributed, sparse and delayed behavior remains difficult |

## Missing detection branches

- Primary missing or weak branch: command-line fallback for missing LSA telemetry.
- Neither rule can compensate for absent collection or unbounded extension behavior.
- Tool attribution is not inferred from shared behavior.

## Detection edge cases and blind spots

- Stable process identity can be lost through PID reuse, parser mismatch or sensor restart.
- Low-volume, distributed and delayed activity may fall outside the correlation window or threshold.
- Vendor semantic events require tenant verification; configurable names and infrastructure are not reliable gates.
- Benign administration, monitoring and security products can produce overlapping effects.

## Signal-quality assessment

- Our primary signal: LSA ticket mutation followed by resource use; `moderate` to `strong` because it correlates behavior/effect but remains telemetry-dependent.
- Public primary signal: command-line ticket listing or purge; strength varies with proximity to the effect and reliance on mutable implementation details.
- Scoped conclusion: `ours_stronger` for the listed procedures only.

## Public-rule weaknesses

- The candidate is narrower, implementation-specific, product-specific, or absent for some Havoc branches.
- Public exclusions, thresholds and data-model assumptions are not trusted without independent validation.

## Internal-rule weaknesses

- command-line fallback for missing LSA telemetry.
- Canonical joins and thresholds remain experimental pending representative tenant fixtures.

## Decision trail

- Candidate improvement: command-line fallback for missing LSA telemetry
- Independent verification: pinned Havoc report, internal review, telemetry contract and candidate hash/path above
- Decision: `rejected`
- Reason: The public branch depends on mutable names or command implementation and would weaken behavioral coverage; proposal is retained only as unvalidated comparative code.
- Required regeneration: canonical review, telemetry, translations, dependencies and comparison when adopted

## Unmatched scope

- Public logic does not bound Havoc external services, in-memory job state or unavailable victim/server telemetry.
- Our logic does not inherit candidate-specific allowlists, ML models or command-name coverage.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: command-line fallback for missing LSA telemetry
- Required telemetry: concrete KERBEROS_TICKET_SUBMIT and KERBEROS_RESOURCE_AUTHENTICATION mappings with stable entity fields and collection health
- Validation status: `unvalidated_proposal`

```yaral
rule havoc_kerberos_ticket_effect_proposal {
  meta:
    status = "experimental"
    validation_status = "unvalidated_proposal"
  events:
    $a.metadata.product_event_type = "KERBEROS_TICKET_SUBMIT"
    $a.principal.hostname = $host
    $a.principal.process.product_specific_process_id = $pid
    $b.metadata.product_event_type = "KERBEROS_RESOURCE_AUTHENTICATION"
    $b.principal.hostname = $host
    $b.principal.process.product_specific_process_id = $pid
  match:
    $host, $pid over 10m
  condition:
    $a and $b
}
```

This proposal is actual detection logic for the scoped missing branch, not an automatic adoption. It must be compiled, mapped, benign-baselined and adversarially reviewed before canonical use. The only accepted comparison change in this pass is the independently implemented stable-destination recurrence rule documented above.