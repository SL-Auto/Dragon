# Public-rule comparison: sliver_remote_admin_sequence

## Identity and independence gate

- Internal tool: `sliver`
- Internal canonical rule: `detections/sliver/yaral/sliver_remote_admin_sequence.yaral`
- Internal SHA-256: `7e3aecb58a46abde8ed1b771bcec5b6c442b77a8944f012112b056ccecba41e3`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-020`
- Scope mapping rationale: procedure, ordered behavior, security effect, platform and telemetry; names and syntax were not mapping criteria.

Public candidate:
- [`public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/lateral_movement_remote_services.toml`](../../public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/lateral_movement_remote_services.toml) - SHA-256 `613041568e8a969bee0ae85cd94b19dd714ffccb2780dfea5c478fb9f978906d`

## Procedure and detection-branch matrix

| Procedure branch / effect | Ours | Public | Primary signal and strength | Compensating signal | Conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Process/session prerequisite | Partial process or identity context | Adjacent behavior only | Stable process/session entity - moderate | signer, first-seen and host-role context | complementary | Internal `PROC-020` inventory; cited candidate. |
| remote authentication is followed by service or SSH execution | Principal event family covered | Overlapping behavior under candidate-specific assumptions | remote session identifier joined to service/SSH execution and resulting child - strong | ordered child/file/network/state effect - moderate | complementary | Security effect is closer to procedure than a tool name. |
| Result, recurrence or cleanup | Partial or absent | Partial or outside scope | Verified resulting state - strong | subsequent access, transfer, deletion or authentication - moderate | different_scope | Neither rule closes every downstream branch. |

## Missing detection branches

- Missing from ours: Host and user joins can associate unrelated administration; stable logon/session identity, source continuity and created process are absent.
- Missing from public: The public candidate does not cover complete Sliver procedure ordering, the internal process-to-effect correlation, or tool-name-independent downstream confirmation.
- Missing from both: activity split across processes/hosts, low-and-slow execution, encrypted application content, telemetry outages, and reliable confirmation of operator intent.

## Detection edge cases and blind spots

Process identifiers can be reused and differ across sensors; prefer a sensor-issued process entity ID when available. NAT, proxies, resolver infrastructure, delayed ingestion, clock skew and partial endpoint visibility can break ordering. Legitimate software deployment, remote support, browsers, proxies, backup, monitoring and administration overlap with individual primitives. Baselines should raise or lower confidence without excluding the sensitive effect. Distributed and low-rate activity needs longer-lived entity analytics rather than simply expanding every correlation window.

## Signal-quality assessment

| Signal | Strength | Used by | Reason | Fragility |
| --- | --- | --- | --- | --- |
| remote session identifier joined to service/SSH execution and resulting child | strong | proposed refinement | Close to the security effect and behavior-based. | Requires stable entity joins and declared telemetry. |
| Process-attributed egress | moderate | ours | Valuable causal context but common alone. | Proxying and sensor gaps reduce attribution. |
| Image, argument, port or default name | weak | some public logic | Useful enrichment, not durable intent. | Mutable and common in benign workloads. |

## Public-rule weaknesses

The candidate supplies useful behaviorally relevant telemetry but not the whole Sliver procedure. Backend assumptions and fixed thresholds are not tenant validation; its predicates must not be copied blindly.

## Internal-rule weaknesses

Host and user joins can associate unrelated administration; stable logon/session identity, source continuity and created process are absent. Broad joins risk benign collisions; narrow windows and same-process assumptions risk false negatives during delayed, delegated or distributed behavior.

## Decision trail

- Candidate improvement: independently implement and test the strong branch below.
- Independent verification: pinned Sliver source, provider semantics, schema mappings and authorized sanitized fixtures required.
- Decision: `deferred_pending_rule_improvement_run`
- Reason: comparative evidence is not canonical authority; proposal has not passed adversarial review.
- Required regeneration: canonical detection review, coverage, telemetry/master, five translations, dependencies/manifests/hashes, then re-comparison.

## Unmatched scope

The candidate does not cover all of `PROC-020`. No global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: Host and user joins can associate unrelated administration; stable logon/session identity, source continuity and created process are absent.
- Required telemetry: stable process/session entity, actor, host, event time, action/result and procedure-specific file/network/state fields.
- Validation status: `unvalidated_proposal`

```yaral
rule sliver_remote_admin_sequence_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-020"
    source_comparison = "unvalidated_proposal"
  events:
    $l.metadata.product_event_type = /4624|sshd_auth_success/
    $l.principal.ip = $source
    $l.target.hostname = $host
    $l.target.user.userid = $user
    $l.network.session_id = $session
    $x.metadata.product_event_type = /4697|7045|sshd_command/
    $x.principal.user.userid = $user
    $x.target.hostname = $host
    $x.network.session_id = $session
    $l.metadata.event_timestamp.seconds <= $x.metadata.event_timestamp.seconds
  match:
    $source, $host, $user, $session over 10m
  condition:
    $l and $x
}
```

The proposal uses concrete telemetry semantics but does not prove tool identity. It remains limited by collection health, process-entity fidelity, enrichment quality and activity outside the window. If accepted or modified, complete the full downstream workflow; if rejected, preserve the rationale without changing canonical logic.
