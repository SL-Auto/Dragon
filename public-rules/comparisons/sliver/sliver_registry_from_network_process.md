# Public-rule comparison: sliver_registry_from_network_process

## Identity and independence gate

- Internal tool: `sliver`
- Internal canonical rule: `detections/sliver/yaral/sliver_registry_from_network_process.yaral`
- Internal SHA-256: `9985462cab2ae7c6771504d3ad3a03b219c47e96dca66a7a1a17cf0d17458210`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-018`
- Scope mapping rationale: procedure, ordered behavior, security effect, platform and telemetry; names and syntax were not mapping criteria.

Public candidate:
- [`public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/persistence_registry_uncommon.toml`](../../public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/persistence_registry_uncommon.toml) - SHA-256 `c674ef7924667af57ec383ddf1b463d3581ed07d48d8d4c7bc951159da185942`

## Procedure and detection-branch matrix

| Procedure branch / effect | Ours | Public | Primary signal and strength | Compensating signal | Conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Process/session prerequisite | Partial process or identity context | Adjacent behavior only | Stable process/session entity - moderate | signer, first-seen and host-role context | complementary | Internal `PROC-018` inventory; cited candidate. |
| network-active process mutates registry state | Principal event family covered | Overlapping behavior under candidate-specific assumptions | network-active process writes a sensitive persistence or security-control key - strong | ordered child/file/network/state effect - moderate | complementary | Security effect is closer to procedure than a tool name. |
| Result, recurrence or cleanup | Partial or absent | Partial or outside scope | Verified resulting state - strong | subsequent access, transfer, deletion or authentication - moderate | different_scope | Neither rule closes every downstream branch. |

## Missing detection branches

- Missing from ours: Any registry mutation is too broad; security-sensitive keys, before/after value, persistence effect and process entity join are missing.
- Missing from public: The public candidate does not cover complete Sliver procedure ordering, the internal process-to-effect correlation, or tool-name-independent downstream confirmation.
- Missing from both: activity split across processes/hosts, low-and-slow execution, encrypted application content, telemetry outages, and reliable confirmation of operator intent.

## Detection edge cases and blind spots

Process identifiers can be reused and differ across sensors; prefer a sensor-issued process entity ID when available. NAT, proxies, resolver infrastructure, delayed ingestion, clock skew and partial endpoint visibility can break ordering. Legitimate software deployment, remote support, browsers, proxies, backup, monitoring and administration overlap with individual primitives. Baselines should raise or lower confidence without excluding the sensitive effect. Distributed and low-rate activity needs longer-lived entity analytics rather than simply expanding every correlation window.

## Signal-quality assessment

| Signal | Strength | Used by | Reason | Fragility |
| --- | --- | --- | --- | --- |
| network-active process writes a sensitive persistence or security-control key | strong | proposed refinement | Close to the security effect and behavior-based. | Requires stable entity joins and declared telemetry. |
| Process-attributed egress | moderate | ours | Valuable causal context but common alone. | Proxying and sensor gaps reduce attribution. |
| Image, argument, port or default name | weak | some public logic | Useful enrichment, not durable intent. | Mutable and common in benign workloads. |

## Public-rule weaknesses

The candidate supplies useful behaviorally relevant telemetry but not the whole Sliver procedure. Backend assumptions and fixed thresholds are not tenant validation; its predicates must not be copied blindly.

## Internal-rule weaknesses

Any registry mutation is too broad; security-sensitive keys, before/after value, persistence effect and process entity join are missing. Broad joins risk benign collisions; narrow windows and same-process assumptions risk false negatives during delayed, delegated or distributed behavior.

## Decision trail

- Candidate improvement: independently implement and test the strong branch below.
- Independent verification: pinned Sliver source, provider semantics, schema mappings and authorized sanitized fixtures required.
- Decision: `deferred_pending_rule_improvement_run`
- Reason: comparative evidence is not canonical authority; proposal has not passed adversarial review.
- Required regeneration: canonical detection review, coverage, telemetry/master, five translations, dependencies/manifests/hashes, then re-comparison.

## Unmatched scope

The candidate does not cover all of `PROC-018`. No global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: Any registry mutation is too broad; security-sensitive keys, before/after value, persistence effect and process entity join are missing.
- Required telemetry: stable process/session entity, actor, host, event time, action/result and procedure-specific file/network/state fields.
- Validation status: `unvalidated_proposal`

```yaral
rule sliver_registry_from_network_process_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-018"
    source_comparison = "unvalidated_proposal"
  events:
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.process.pid = $pid
    $n.network.direction = "OUTBOUND"
    $r.metadata.event_type = "REGISTRY_MODIFICATION"
    $r.principal.process.pid = $pid
    $r.target.registry.registry_key = /(?i)\\(Run|RunOnce|Services|Winlogon|Image File Execution Options|Terminal Server)\\?/
  match:
    $pid over 15m
  condition:
    $n and $r
}
```

The proposal uses concrete telemetry semantics but does not prove tool identity. It remains limited by collection health, process-entity fidelity, enrichment quality and activity outside the window. If accepted or modified, complete the full downstream workflow; if rejected, preserve the rationale without changing canonical logic.
