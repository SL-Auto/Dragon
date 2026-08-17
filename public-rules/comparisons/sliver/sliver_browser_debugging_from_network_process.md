# Public-rule comparison: sliver_browser_debugging_from_network_process

## Identity and independence gate

- Internal tool: `sliver`
- Internal canonical rule: `detections/sliver/yaral/sliver_browser_debugging_from_network_process.yaral`
- Internal SHA-256: `af912a0a2cf3776d942aa2fafcb20efe3fd623068d8445eeca317e0e9dc93fc1`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-022`
- Scope mapping rationale: procedure, ordered behavior, security effect, platform and telemetry; names and syntax were not mapping criteria.

Public candidate:
- No credible behaviorally comparable public rule was found in the pinned corpus; candidate evidence status: `insufficient_evidence`.

## Procedure and detection-branch matrix

| Procedure branch / effect | Ours | Public | Primary signal and strength | Compensating signal | Conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Process/session prerequisite | Partial process or identity context | Adjacent behavior only | Stable process/session entity - moderate | signer, first-seen and host-role context | complementary | Internal `PROC-022` inventory; cited candidate. |
| network-active process starts a browser debugging endpoint | Principal event family covered | No credible counterpart; not scored | browser process with debugging option plus local listener and parent egress - strong | ordered child/file/network/state effect - moderate | insufficient_evidence | Security effect is closer to procedure than a tool name. |
| Result, recurrence or cleanup | Partial or absent | Partial or outside scope | Verified resulting state - strong | subsequent access, transfer, deletion or authentication - moderate | different_scope | Neither rule closes every downstream branch. |

## Missing detection branches

- Missing from ours: The join does not require a debugging switch, bind address, listener, or browser child identity.
- Missing from public: No public counterpart was identified, so public branch coverage is unknown rather than assumed absent.
- Missing from both: activity split across processes/hosts, low-and-slow execution, encrypted application content, telemetry outages, and reliable confirmation of operator intent.

## Detection edge cases and blind spots

Process identifiers can be reused and differ across sensors; prefer a sensor-issued process entity ID when available. NAT, proxies, resolver infrastructure, delayed ingestion, clock skew and partial endpoint visibility can break ordering. Legitimate software deployment, remote support, browsers, proxies, backup, monitoring and administration overlap with individual primitives. Baselines should raise or lower confidence without excluding the sensitive effect. Distributed and low-rate activity needs longer-lived entity analytics rather than simply expanding every correlation window.

## Signal-quality assessment

| Signal | Strength | Used by | Reason | Fragility |
| --- | --- | --- | --- | --- |
| browser process with debugging option plus local listener and parent egress | strong | proposed refinement | Close to the security effect and behavior-based. | Requires stable entity joins and declared telemetry. |
| Process-attributed egress | moderate | ours | Valuable causal context but common alone. | Proxying and sensor gaps reduce attribution. |
| Image, argument, port or default name | weak | some public logic | Useful enrichment, not durable intent. | Mutable and common in benign workloads. |

## Public-rule weaknesses

No candidate was forced into this comparison. The pinned corpus provides insufficient evidence for a public-versus-internal branch conclusion.

## Internal-rule weaknesses

The join does not require a debugging switch, bind address, listener, or browser child identity. Broad joins risk benign collisions; narrow windows and same-process assumptions risk false negatives during delayed, delegated or distributed behavior.

## Decision trail

- Candidate improvement: independently implement and test the strong branch below.
- Independent verification: pinned Sliver source, provider semantics, schema mappings and authorized sanitized fixtures required.
- Decision: `deferred_pending_rule_improvement_run`
- Reason: comparative evidence is not canonical authority; proposal has not passed adversarial review.
- Required regeneration: canonical detection review, coverage, telemetry/master, five translations, dependencies/manifests/hashes, then re-comparison.

## Unmatched scope

The candidate does not cover all of `PROC-022`. No global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: The join does not require a debugging switch, bind address, listener, or browser child identity.
- Required telemetry: stable process/session entity, actor, host, event time, action/result and procedure-specific file/network/state fields.
- Validation status: `unvalidated_proposal`

```yaral
rule sliver_browser_debugging_from_network_process_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-022"
    source_comparison = "unvalidated_proposal"
  events:
    $p.metadata.event_type = "PROCESS_LAUNCH"
    $p.principal.process.pid = $parent_pid
    $p.target.process.pid = $browser_pid
    $p.target.process.command_line = /(?i)--remote-debugging-(port|pipe)/
    $l.metadata.event_type = "NETWORK_CONNECTION"
    $l.principal.process.pid = $browser_pid
    $l.network.direction = "LISTENING"
    $l.target.port = $debug_port
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.process.pid = $parent_pid
    $n.network.direction = "OUTBOUND"
    $p.metadata.event_timestamp.seconds <= $l.metadata.event_timestamp.seconds
  match:
    $parent_pid, $browser_pid over 5m
  condition:
    $p and $l and $n
}
```

The proposal uses concrete telemetry semantics but does not prove tool identity. It remains limited by collection health, process-entity fidelity, enrichment quality and activity outside the window. If accepted or modified, complete the full downstream workflow; if rejected, preserve the rationale without changing canonical logic.
