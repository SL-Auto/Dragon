# Public-rule comparison: sliver_cleanup_after_egress

## Identity and independence gate

- Internal tool: `sliver`
- Internal canonical rule: `detections/sliver/yaral/sliver_cleanup_after_egress.yaral`
- Internal SHA-256: `73961295c1f69271085280dba6de169c93896daa5ff71388b501216c0f502f79`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-002,PROC-026`
- Scope mapping rationale: procedure, ordered behavior, security effect, platform and telemetry; names and syntax were not mapping criteria.

Public candidate:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/linux/defense_evasion_log_files_deleted.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/linux/defense_evasion_log_files_deleted.toml) - SHA-256 `b34c11414e36e68e284e57aaaf55f301c623431f26535de705f11024d6975727`

## Procedure and detection-branch matrix

| Procedure branch / effect | Ours | Public | Primary signal and strength | Compensating signal | Conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Process/session prerequisite | Partial process or identity context | Adjacent behavior only | Stable process/session entity - moderate | signer, first-seen and host-role context | complementary | Internal `PROC-002,PROC-026` inventory; cited candidate. |
| egressing process removes its image or operational artifacts | Principal event family covered | Overlapping behavior under candidate-specific assumptions | same process entity deletes its executable after egress - strong | ordered child/file/network/state effect - moderate | complementary | Security effect is closer to procedure than a tool name. |
| Result, recurrence or cleanup | Partial or absent | Partial or outside scope | Verified resulting state - strong | subsequent access, transfer, deletion or authentication - moderate | different_scope | Neither rule closes every downstream branch. |

## Missing detection branches

- Missing from ours: Deletion and network events can be unrelated on a busy host because stable process and file identity are not proven.
- Missing from public: The public candidate does not cover complete Sliver procedure ordering, the internal process-to-effect correlation, or tool-name-independent downstream confirmation.
- Missing from both: activity split across processes/hosts, low-and-slow execution, encrypted application content, telemetry outages, and reliable confirmation of operator intent.

## Detection edge cases and blind spots

Process identifiers can be reused and differ across sensors; prefer a sensor-issued process entity ID when available. NAT, proxies, resolver infrastructure, delayed ingestion, clock skew and partial endpoint visibility can break ordering. Legitimate software deployment, remote support, browsers, proxies, backup, monitoring and administration overlap with individual primitives. Baselines should raise or lower confidence without excluding the sensitive effect. Distributed and low-rate activity needs longer-lived entity analytics rather than simply expanding every correlation window.

## Signal-quality assessment

| Signal | Strength | Used by | Reason | Fragility |
| --- | --- | --- | --- | --- |
| same process entity deletes its executable after egress | strong | proposed refinement | Close to the security effect and behavior-based. | Requires stable entity joins and declared telemetry. |
| Process-attributed egress | moderate | ours | Valuable causal context but common alone. | Proxying and sensor gaps reduce attribution. |
| Image, argument, port or default name | weak | some public logic | Useful enrichment, not durable intent. | Mutable and common in benign workloads. |

## Public-rule weaknesses

The candidate supplies useful behaviorally relevant telemetry but not the whole Sliver procedure. Backend assumptions and fixed thresholds are not tenant validation; its predicates must not be copied blindly.

## Internal-rule weaknesses

Deletion and network events can be unrelated on a busy host because stable process and file identity are not proven. Broad joins risk benign collisions; narrow windows and same-process assumptions risk false negatives during delayed, delegated or distributed behavior.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/sliver/detection-review.md`.
- Prior state: this trail still read `deferred_pending_rule_improvement_run`, although the 2026-08-16 backlog resolution (REVIEW-010 to REVIEW-014) had already acted on the proposal; this pass re-reviews that action and records the terminal decision.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - Process and file identity are proven by joining the deleted file's SHA-256 to the egressing process image hash on the same host and PID.
  - Removed the proposal's `event_timestamp.seconds <=` ordering; bounded co-occurrence in the match window is kept (REVIEW-010).
  - Adopted as an additional narrow rule beside the broad base rule, not as a replacement, so procedures without the narrow sub-case keep coverage (REVIEW-012).
- Canonical result: `detections/sliver/yaral/sliver_cleanup_after_egress.yaral`, SHA-256 `bd5f75c9e717feeabf121342bd62d0e45b00abee9cb8a06aca39aba4272c4ccb`.
- Canonical result: `detections/sliver/yaral/sliver_self_delete_after_egress.yaral`, SHA-256 `d1e9ba00923a48f8a54ff2be52cc9d52b8e056000ba53fb1eb29a43197e77470`.
- Regeneration: coverage, telemetry, `telemetry/MASTER.md`, five translations and dependency hashes were regenerated on 2026-08-16 when the rule was adopted; re-verified present and hash-consistent on 2026-11-21.

## Unmatched scope

The candidate does not cover all of `PROC-002,PROC-026`. No global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: Deletion and network events can be unrelated on a busy host because stable process and file identity are not proven.
- Required telemetry: stable process/session entity, actor, host, event time, action/result and procedure-specific file/network/state fields.
- Validation status: `unvalidated_proposal`

```yaral
rule sliver_cleanup_after_egress_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-002,PROC-026"
    source_comparison = "unvalidated_proposal"
  events:
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.process.file.sha256 = $hash
    $n.principal.process.pid = $pid
    $n.network.direction = "OUTBOUND"
    $d.metadata.event_type = "FILE_DELETION"
    $d.principal.process.pid = $pid
    $d.target.file.sha256 = $hash
    $n.metadata.event_timestamp.seconds <= $d.metadata.event_timestamp.seconds
  match:
    $pid, $hash over 30m
  condition:
    $n and $d
}
```

The proposal uses concrete telemetry semantics but does not prove tool identity. It remains limited by collection health, process-entity fidelity, enrichment quality and activity outside the window. If accepted or modified, complete the full downstream workflow; if rejected, preserve the rationale without changing canonical logic.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/linux/defense_evasion_log_files_deleted.toml` changed between 7e91c15 and 9d792a8; re-read on 2026-11-21: only a reference URL and classification metadata changed, the query is identical, and the conclusions are unaffected.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Egressing process deletes its own image | covered by `sliver_self_delete_after_egress` (hash plus PID) | `defense_evasion_log_files_deleted.toml`: Linux log-file deletion only | deleted file hash equals egressing image hash - strong | base cleanup rule - moderate | ours_stronger |
| Deletion of other operational artifacts after egress | covered by base `sliver_cleanup_after_egress` | partially overlapping on Linux log paths | same-process deletion after egress - moderate | none | complementary |
| Linux system-log destruction | not targeted | covered | log-path deletion - moderate | none | different_scope |

- Current canonical YARA-L `detections/sliver/yaral/sliver_cleanup_after_egress.yaral` (`experimental` / `needs_validation`):

```yaral
rule sliver_cleanup_after_egress {
  meta:
    author = "Detection Research Agent"
    description = "Network process deletes its own image or related artifacts"
    date = "2026-08-15"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Correlates teardown with prior remote channel"
    procedure_ids = "PROC-002,PROC-026"
    log_source_prerequisites = "File deletion and network telemetry with stable PID"
    false_positives = "Installers, updaters, temporary utilities"
    references = "reports/sliver/source-analysis.md"
    validation_status = "needs_validation"
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/sliver/detection-review.md"
  events:
    $d.metadata.event_type = "FILE_DELETION"
    $d.principal.hostname = $host
    $d.principal.process.product_specific_process_id = $pid

    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.network.direction = "OUTBOUND"
    $n.principal.hostname = $host
    $n.principal.process.product_specific_process_id = $pid
  match: $host, $pid over 15m
  condition: $d and $n
}
```

- Current canonical YARA-L `detections/sliver/yaral/sliver_self_delete_after_egress.yaral` (`experimental` / `needs_validation`):

```yaral
rule sliver_self_delete_after_egress {
  meta:
    author = "Detection Research Agent"
    description = "A process with outbound network activity deletes a file matching its own executable hash"
    date = "2026-08-16"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Same-hash self-deletion after egress is a high-specificity teardown signal; compensates for the broad cleanup rule where stable process/file identity between deletion and egress is not proven"
    procedure_ids = "PROC-002,PROC-026"
    log_source_prerequisites = "EDR file-deletion telemetry with file hash, and process-attributed network telemetry with file hash, sharing a stable process entity"
    false_positives = "Self-updating software and installers that replace or remove their own binary after execution"
    references = "reports/sliver/source-analysis.md, public-rules/comparisons/sliver/sliver_cleanup_after_egress.md"
    validation_status = "needs_validation"
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/sliver/detection-review.md"
    source_comparison = "accepted_as_compensating_rule_from_unvalidated_proposal"
  events:
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.network.direction = "OUTBOUND"
    $n.principal.hostname = $host
    $n.principal.process.product_specific_process_id = $pid
    $n.principal.process.file.sha256 = $hash

    $d.metadata.event_type = "FILE_DELETION"
    $d.principal.hostname = $host
    $d.principal.process.product_specific_process_id = $pid
    $d.target.file.sha256 = $hash
  match: $host, $pid, $hash over 30m
  condition: $n and $d
}
```

- Re-comparison outcome: the current canonical rule set closes the branch the proposal targeted, within declared telemetry. Remaining limits are the accepted gaps in `reviews/sliver/detection-review.md`.
