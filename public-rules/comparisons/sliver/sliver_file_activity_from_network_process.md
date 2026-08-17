# Public-rule comparison: sliver_file_activity_from_network_process

## Identity and independence gate

- Internal tool: `sliver`
- Internal canonical rule: `detections/sliver/yaral/sliver_file_activity_from_network_process.yaral`
- Internal SHA-256: `7bc97d7f36f98463ce7c984c4203a230eefa7b45e0b835c336042b7e2797ff9c`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-007,PROC-008,PROC-009`
- Scope mapping rationale: procedure, ordered behavior, security effect, platform and telemetry; names and syntax were not mapping criteria.

Public candidate:
- No credible behaviorally comparable public rule was found in the pinned corpus; candidate evidence status: `insufficient_evidence`.

## Procedure and detection-branch matrix

| Procedure branch / effect | Ours | Public | Primary signal and strength | Compensating signal | Conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Process/session prerequisite | Partial process or identity context | Adjacent behavior only | Stable process/session entity - moderate | signer, first-seen and host-role context | complementary | Internal `PROC-007,PROC-008,PROC-009` inventory; cited candidate. |
| network-active process reads, mutates, stages, or deletes files | Principal event family covered | No credible counterpart; not scored | sensitive-file access or archive/staging burst by the same process entity - strong | ordered child/file/network/state effect - moderate | insufficient_evidence | Security effect is closer to procedure than a tool name. |
| Result, recurrence or cleanup | Partial or absent | Partial or outside scope | Verified resulting state - strong | subsequent access, transfer, deletion or authentication - moderate | different_scope | Neither rule closes every downstream branch. |

## Missing detection branches

- Missing from ours: Generic file activity is common and the rule conflates credential access, collection, transfer staging, and cleanup.
- Missing from public: No public counterpart was identified, so public branch coverage is unknown rather than assumed absent.
- Missing from both: activity split across processes/hosts, low-and-slow execution, encrypted application content, telemetry outages, and reliable confirmation of operator intent.

## Detection edge cases and blind spots

Process identifiers can be reused and differ across sensors; prefer a sensor-issued process entity ID when available. NAT, proxies, resolver infrastructure, delayed ingestion, clock skew and partial endpoint visibility can break ordering. Legitimate software deployment, remote support, browsers, proxies, backup, monitoring and administration overlap with individual primitives. Baselines should raise or lower confidence without excluding the sensitive effect. Distributed and low-rate activity needs longer-lived entity analytics rather than simply expanding every correlation window.

## Signal-quality assessment

| Signal | Strength | Used by | Reason | Fragility |
| --- | --- | --- | --- | --- |
| sensitive-file access or archive/staging burst by the same process entity | strong | proposed refinement | Close to the security effect and behavior-based. | Requires stable entity joins and declared telemetry. |
| Process-attributed egress | moderate | ours | Valuable causal context but common alone. | Proxying and sensor gaps reduce attribution. |
| Image, argument, port or default name | weak | some public logic | Useful enrichment, not durable intent. | Mutable and common in benign workloads. |

## Public-rule weaknesses

No candidate was forced into this comparison. The pinned corpus provides insufficient evidence for a public-versus-internal branch conclusion.

## Internal-rule weaknesses

Generic file activity is common and the rule conflates credential access, collection, transfer staging, and cleanup. Broad joins risk benign collisions; narrow windows and same-process assumptions risk false negatives during delayed, delegated or distributed behavior.

## Decision trail

- Candidate improvement: independently implement and test the strong branch below.
- Independent verification: pinned Sliver source, provider semantics, schema mappings and authorized sanitized fixtures required.
- Decision: `deferred_pending_rule_improvement_run`
- Reason: comparative evidence is not canonical authority; proposal has not passed adversarial review.
- Required regeneration: canonical detection review, coverage, telemetry/master, five translations, dependencies/manifests/hashes, then re-comparison.

## Unmatched scope

The candidate does not cover all of `PROC-007,PROC-008,PROC-009`. No global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `split`
- Addresses branches: Generic file activity is common and the rule conflates credential access, collection, transfer staging, and cleanup.
- Required telemetry: stable process/session entity, actor, host, event time, action/result and procedure-specific file/network/state fields.
- Validation status: `unvalidated_proposal`

```yaral
rule sliver_file_activity_from_network_process_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-007,PROC-008,PROC-009"
    source_comparison = "unvalidated_proposal"
  events:
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.process.pid = $pid
    $n.network.direction = "OUTBOUND"
    $f.metadata.event_type = /FILE_READ|FILE_CREATION|FILE_MODIFICATION|FILE_DELETION/
    $f.principal.process.pid = $pid
    $f.target.file.full_path = /(?i)(\\Windows\\System32\\config\\(SAM|SECURITY|SYSTEM)|ntds\.dit|\\Users\\[^\\]+\\AppData\\.*(Login Data|Cookies))/
  match:
    $pid over 15m
  condition:
    $n and $f
}
```

The proposal uses concrete telemetry semantics but does not prove tool identity. It remains limited by collection health, process-entity fidelity, enrichment quality and activity outside the window. If accepted or modified, complete the full downstream workflow; if rejected, preserve the rationale without changing canonical logic.
