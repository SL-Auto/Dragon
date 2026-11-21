# Public-rule comparison: havoc_named_pipe_network_context

## Identity and independence gate

- Internal rule: `detections/havoc/yaral/havoc_named_pipe_network_context.yaral`
- Internal SHA-256: `dc178ad4a086091edcc460ce421b7387a0f42ffd22068da6a6c815d8dd8151d4`
- Internal review completed before public comparison: `true`
- Procedures: HV-P02, HV-P15
- Public candidates were consulted only after independent source analysis, rule generation and adversarial review.

- [`public-rules/snapshots/splunk-security-content/21509485465aaed2cfa4604e3d2ab5ee52975f0a/detections/endpoint/windows_suspicious_named_pipe.yml`](../../snapshots/splunk-security-content/21509485465aaed2cfa4604e3d2ab5ee52975f0a/detections/endpoint/windows_suspicious_named_pipe.yml) - SHA-256 `ea15f3bf7c753041a93b704480868c0bbf6c8bd4af5010e00e259ba50f898154`

## Procedure and detection-branch matrix

| Branch | Our rule | Public rule | Primary signal and strength | Gap |
| --- | --- | --- | --- | --- |
| Preconditions and context | process/entity context | source-specific context | moderate â€” establishes causal scope | Both depend on source completeness |
| Security-sensitive action | same-process pipe and network behavior | known or suspicious pipe naming | strong when close to the effect; weak when name/default based | remote SMB session confirmation |
| Resulting effect | correlated endpoint/network effect | candidate-specific effect | moderate to strong depending parser fidelity | Missing entity fields break joins |
| Cleanup or low-and-slow | partial | partial or absent | weak â€” neither proves completeness | Distributed, sparse and delayed behavior remains difficult |

## Missing detection branches

- Primary missing or weak branch: remote SMB session confirmation.
- Neither rule can compensate for absent collection or unbounded extension behavior.
- Tool attribution is not inferred from shared behavior.

## Detection edge cases and blind spots

- Stable process identity can be lost through PID reuse, parser mismatch or sensor restart.
- Low-volume, distributed and delayed activity may fall outside the correlation window or threshold.
- Vendor semantic events require tenant verification; configurable names and infrastructure are not reliable gates.
- Benign administration, monitoring and security products can produce overlapping effects.

## Signal-quality assessment

- Our primary signal: same-process pipe and network behavior; `moderate` to `strong` because it correlates behavior/effect but remains telemetry-dependent.
- Public primary signal: known or suspicious pipe naming; strength varies with proximity to the effect and reliance on mutable implementation details.
- Scoped conclusion: `ours_stronger` for the listed procedures only.

## Public-rule weaknesses

- The candidate is narrower, implementation-specific, product-specific, or absent for some Havoc branches.
- Public exclusions, thresholds and data-model assumptions are not trusted without independent validation.

## Internal-rule weaknesses

- remote SMB session confirmation.
- Canonical joins and thresholds remain experimental pending representative tenant fixtures.

## Decision trail

- Candidate improvement: remote SMB session confirmation
- Independent verification: pinned Havoc report, internal review, telemetry contract and candidate hash/path above
- Decision: `reject`
- Label normalized (2026-11-21): the earlier token `rejected` is replaced by the contract's terminal value `reject`; the decision and its reasoning are unchanged.
- Reason: The public branch depends on mutable names or command implementation and would weaken behavioral coverage; proposal is retained only as unvalidated comparative code.
- Required regeneration: canonical review, telemetry, translations, dependencies and comparison when adopted

## Unmatched scope

- Public logic does not bound Havoc external services, in-memory job state or unavailable victim/server telemetry.
- Our logic does not inherit candidate-specific allowlists, ML models or command-name coverage.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: remote SMB session confirmation
- Required telemetry: concrete NAMED_PIPE_CREATE and SMB_SESSION mappings with stable entity fields and collection health
- Validation status: `unvalidated_proposal`

```yaral
rule havoc_named_pipe_network_context_proposal {
  meta:
    status = "experimental"
    validation_status = "unvalidated_proposal"
  events:
    $a.metadata.product_event_type = "NAMED_PIPE_CREATE"
    $a.principal.hostname = $host
    $a.principal.process.product_specific_process_id = $pid
    $b.metadata.product_event_type = "SMB_SESSION"
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
- `detections/endpoint/windows_suspicious_named_pipe.yml` changed between 457ce9f and 2150948; re-read on 2026-11-21: the lookup gained `local=t` (execution locality only); the pipe-name logic is identical. The comparison conclusions and decision are unaffected.
