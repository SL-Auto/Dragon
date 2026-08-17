# Public-rule comparison: sliver_identity_or_service_from_network_process

## Identity and independence gate

- Internal tool: `sliver`
- Internal canonical rule: `detections/sliver/yaral/sliver_identity_or_service_from_network_process.yaral`
- Internal SHA-256: `73ef2e2699a7255f2a3a5426fe7ed971a018b289d04b33f1f62c5faeb5000169`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-016,PROC-017,PROC-019`
- Scope mapping rationale: procedure, ordered behavior, security effect, platform and telemetry; names and syntax were not mapping criteria.

Public candidate:
- [`public-rules/snapshots/chronicle-community/234e9223c3b8f3d1c30209d9663797ba69057533/rules-community/microsoft/windows/win_susp_or_malicious_service_created.yaral`](../../public-rules/snapshots/chronicle-community/234e9223c3b8f3d1c30209d9663797ba69057533/rules-community/microsoft/windows/win_susp_or_malicious_service_created.yaral) - SHA-256 `ffca062a76c08fcc3917a87424760bba8042c956275b072e962943ac5f3803f7`

## Procedure and detection-branch matrix

| Procedure branch / effect | Ours | Public | Primary signal and strength | Compensating signal | Conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Process/session prerequisite | Partial process or identity context | Adjacent behavior only | Stable process/session entity - moderate | signer, first-seen and host-role context | complementary | Internal `PROC-016,PROC-017,PROC-019` inventory; cited candidate. |
| network-active identity performs explicit-credential, privilege, or service operations | Principal event family covered | Overlapping behavior under candidate-specific assumptions | stable process/logon session joined to explicit credentials and resulting privileged action - strong | ordered child/file/network/state effect - moderate | complementary | Security effect is closer to procedure than a tool name. |
| Result, recurrence or cleanup | Partial or absent | Partial or outside scope | Verified resulting state - strong | subsequent access, transfer, deletion or authentication - moderate | different_scope | Neither rule closes every downstream branch. |

## Missing detection branches

- Missing from ours: Four event families with different meanings are conflated and account-based correlation can join unrelated processes.
- Missing from public: The public candidate does not cover complete Sliver procedure ordering, the internal process-to-effect correlation, or tool-name-independent downstream confirmation.
- Missing from both: activity split across processes/hosts, low-and-slow execution, encrypted application content, telemetry outages, and reliable confirmation of operator intent.

## Detection edge cases and blind spots

Process identifiers can be reused and differ across sensors; prefer a sensor-issued process entity ID when available. NAT, proxies, resolver infrastructure, delayed ingestion, clock skew and partial endpoint visibility can break ordering. Legitimate software deployment, remote support, browsers, proxies, backup, monitoring and administration overlap with individual primitives. Baselines should raise or lower confidence without excluding the sensitive effect. Distributed and low-rate activity needs longer-lived entity analytics rather than simply expanding every correlation window.

## Signal-quality assessment

| Signal | Strength | Used by | Reason | Fragility |
| --- | --- | --- | --- | --- |
| stable process/logon session joined to explicit credentials and resulting privileged action | strong | proposed refinement | Close to the security effect and behavior-based. | Requires stable entity joins and declared telemetry. |
| Process-attributed egress | moderate | ours | Valuable causal context but common alone. | Proxying and sensor gaps reduce attribution. |
| Image, argument, port or default name | weak | some public logic | Useful enrichment, not durable intent. | Mutable and common in benign workloads. |

## Public-rule weaknesses

The candidate supplies useful behaviorally relevant telemetry but not the whole Sliver procedure. Backend assumptions and fixed thresholds are not tenant validation; its predicates must not be copied blindly.

## Internal-rule weaknesses

Four event families with different meanings are conflated and account-based correlation can join unrelated processes. Broad joins risk benign collisions; narrow windows and same-process assumptions risk false negatives during delayed, delegated or distributed behavior.

## Decision trail

- Candidate improvement: independently implement and test the strong branch below.
- Independent verification: pinned Sliver source, provider semantics, schema mappings and authorized sanitized fixtures required.
- Decision: `deferred_pending_rule_improvement_run`
- Reason: comparative evidence is not canonical authority; proposal has not passed adversarial review.
- Required regeneration: canonical detection review, coverage, telemetry/master, five translations, dependencies/manifests/hashes, then re-comparison.

## Unmatched scope

The candidate does not cover all of `PROC-016,PROC-017,PROC-019`. No global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `split`
- Addresses branches: Four event families with different meanings are conflated and account-based correlation can join unrelated processes.
- Required telemetry: stable process/session entity, actor, host, event time, action/result and procedure-specific file/network/state fields.
- Validation status: `unvalidated_proposal`

```yaral
rule sliver_identity_or_service_from_network_process_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-016,PROC-017,PROC-019"
    source_comparison = "unvalidated_proposal"
  events:
    $c.metadata.product_event_type = "4648"
    $c.principal.process.pid = $pid
    $c.principal.user.userid = $actor
    $c.target.user.userid = $credential_user
    $s.metadata.product_event_type = /4697|7045/
    $s.principal.user.userid = $credential_user
    $s.target.hostname = $host
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.process.pid = $pid
    $c.metadata.event_timestamp.seconds <= $s.metadata.event_timestamp.seconds
  match:
    $pid, $credential_user, $host over 10m
  condition:
    $c and $s and $n
}
```

The proposal uses concrete telemetry semantics but does not prove tool identity. It remains limited by collection health, process-entity fidelity, enrichment quality and activity outside the window. If accepted or modified, complete the full downstream workflow; if rejected, preserve the rationale without changing canonical logic.
