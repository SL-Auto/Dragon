# Public-rule comparison: sliver_process_behavior_cluster

## Identity and independence gate

- Internal tool: `sliver`
- Internal canonical rule: `detections/sliver/yaral/sliver_process_behavior_cluster.yaral`
- Internal SHA-256: `1b5565b05952d918e04a5edc3fc7772e9d7886daa12b88771fe79e574e62f7d8`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-001`
- Scope mapping rationale: procedure, ordered behavior, security effect, platform and telemetry; names and syntax were not mapping criteria.

Public candidate:
- No credible behaviorally comparable public rule was found in the pinned corpus; candidate evidence status: `insufficient_evidence`.

## Procedure and detection-branch matrix

| Procedure branch / effect | Ours | Public | Primary signal and strength | Compensating signal | Conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Process/session prerequisite | Partial process or identity context | Adjacent behavior only | Stable process/session entity - moderate | signer, first-seen and host-role context | complementary | Internal `PROC-001` inventory; cited candidate. |
| new process begins outbound communication | Principal event family covered | No credible counterpart; not scored | rare unsigned process establishes first-seen external egress and recurs - strong | ordered child/file/network/state effect - moderate | insufficient_evidence | Security effect is closer to procedure than a tool name. |
| Result, recurrence or cleanup | Partial or absent | Partial or outside scope | Verified resulting state - strong | subsequent access, transfer, deletion or authentication - moderate | different_scope | Neither rule closes every downstream branch. |

## Missing detection branches

- Missing from ours: This behavior is ubiquitous and lacks first-seen image, destination reputation, signer, persistence, recurrence, or sensitive follow-on effects.
- Missing from public: No public counterpart was identified, so public branch coverage is unknown rather than assumed absent.
- Missing from both: activity split across processes/hosts, low-and-slow execution, encrypted application content, telemetry outages, and reliable confirmation of operator intent.

## Detection edge cases and blind spots

Process identifiers can be reused and differ across sensors; prefer a sensor-issued process entity ID when available. NAT, proxies, resolver infrastructure, delayed ingestion, clock skew and partial endpoint visibility can break ordering. Legitimate software deployment, remote support, browsers, proxies, backup, monitoring and administration overlap with individual primitives. Baselines should raise or lower confidence without excluding the sensitive effect. Distributed and low-rate activity needs longer-lived entity analytics rather than simply expanding every correlation window.

## Signal-quality assessment

| Signal | Strength | Used by | Reason | Fragility |
| --- | --- | --- | --- | --- |
| rare unsigned process establishes first-seen external egress and recurs | strong | proposed refinement | Close to the security effect and behavior-based. | Requires stable entity joins and declared telemetry. |
| Process-attributed egress | moderate | ours | Valuable causal context but common alone. | Proxying and sensor gaps reduce attribution. |
| Image, argument, port or default name | weak | some public logic | Useful enrichment, not durable intent. | Mutable and common in benign workloads. |

## Public-rule weaknesses

No candidate was forced into this comparison. The pinned corpus provides insufficient evidence for a public-versus-internal branch conclusion.

## Internal-rule weaknesses

This behavior is ubiquitous and lacks first-seen image, destination reputation, signer, persistence, recurrence, or sensitive follow-on effects. Broad joins risk benign collisions; narrow windows and same-process assumptions risk false negatives during delayed, delegated or distributed behavior.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/sliver/detection-review.md`.
- Prior state: this trail still read `deferred_pending_rule_improvement_run`, although the 2026-08-16 backlog resolution (REVIEW-010 to REVIEW-014) had already acted on the proposal; this pass re-reviews that action and records the terminal decision.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - The narrow rule requires a non-VERIFIED process image with at least two outbound connections to one destination in 15 minutes.
  - Dropped the proposal's hard destination-prevalence requirement, which is optional enrichment in `telemetry/sliver.md` (REVIEW-011).
  - Adopted as an additional narrow rule beside the broad base rule, not as a replacement, so procedures without the narrow sub-case keep coverage (REVIEW-012).
  - Re-review: `!= "VERIFIED"` fails open when signature enrichment is absent; this is deliberate and recorded as an accepted gap (REVIEW-017).
- Canonical result: `detections/sliver/yaral/sliver_process_behavior_cluster.yaral`, SHA-256 `d2df6f1775a8747c9aa6dd1c1774ec0f30b2c732463f34770f649e76aab6d983`.
- Canonical result: `detections/sliver/yaral/sliver_unsigned_process_novel_egress.yaral`, SHA-256 `719a173635039eae8871f262f232d031b0d2b69df2fc4f10a2a661e0a5e81b59`.
- Regeneration: coverage, telemetry, `telemetry/MASTER.md`, five translations and dependency hashes were regenerated on 2026-08-16 when the rule was adopted; re-verified present and hash-consistent on 2026-11-21.

## Unmatched scope

The candidate does not cover all of `PROC-001`. No global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: This behavior is ubiquitous and lacks first-seen image, destination reputation, signer, persistence, recurrence, or sensitive follow-on effects.
- Required telemetry: stable process/session entity, actor, host, event time, action/result and procedure-specific file/network/state fields.
- Validation status: `unvalidated_proposal`

```yaral
rule sliver_process_behavior_cluster_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-001"
    source_comparison = "unvalidated_proposal"
  events:
    $p.metadata.event_type = "PROCESS_LAUNCH"
    $p.target.process.pid = $pid
    $p.target.process.file.signature_info.verification_status != "VERIFIED"
    $p.target.process.file.full_path = $image
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.process.pid = $pid
    $n.network.direction = "OUTBOUND"
    $n.target.ip = $destination
    $n.target.resource.attribute.labels["destination_prevalence"] = "rare"
  match:
    $pid, $image, $destination over 15m
  condition:
    $p and $n
}
```

The proposal uses concrete telemetry semantics but does not prove tool identity. It remains limited by collection health, process-entity fidelity, enrichment quality and activity outside the window. If accepted or modified, complete the full downstream workflow; if rejected, preserve the rationale without changing canonical logic.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- All public candidates were re-pinned to the refreshed snapshots; no referenced candidate file changed content.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| New unsigned process begins repeated outbound communication | covered by `sliver_unsigned_process_novel_egress` | no credible counterpart in the pinned snapshots | signature status plus repeated same-destination egress - moderate | base cluster rule - weak | ours_stronger |
| Signed or side-loaded implant host | base rule only | not covered | behavior cluster - weak | none | ours_stronger |

- Current canonical YARA-L `detections/sliver/yaral/sliver_process_behavior_cluster.yaral` (`experimental` / `needs_validation`):

```yaral
rule sliver_process_behavior_cluster {
  meta:
    author = "Detection Research Agent"
    description = "New process followed by outbound activity"
    date = "2026-08-15"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "Links implant lifecycle to egress"
    procedure_ids = "PROC-001"
    log_source_prerequisites = "Process launch and process network UDM with stable PID"
    false_positives = "New legitimate network software"
    references = "reports/sliver/source-analysis.md"
    validation_status = "needs_validation"
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/sliver/detection-review.md"
  events:
    $p.metadata.event_type = "PROCESS_LAUNCH"
    $p.principal.hostname = $host
    $p.target.process.product_specific_process_id = $pid

    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.hostname = $host
    $n.principal.process.product_specific_process_id = $pid
    $n.network.direction = "OUTBOUND"
  match: $host, $pid over 10m
  condition: $p and $n
}
```

- Current canonical YARA-L `detections/sliver/yaral/sliver_unsigned_process_novel_egress.yaral` (`experimental` / `needs_validation`):

```yaral
rule sliver_unsigned_process_novel_egress {
  meta:
    author = "Detection Research Agent"
    description = "An unsigned, newly launched process establishes outbound network activity to the same destination more than once"
    date = "2026-08-16"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "Signature-verification status plus per-destination recurrence narrows the ubiquitous new-process-plus-egress shape flagged as weak in review; the original broad rule is retained so signed-build or single-connection implant activity is not silently dropped"
    procedure_ids = "PROC-001"
    log_source_prerequisites = "Process launch telemetry with code-signature verification status, plus process-attributed outbound network telemetry with destination"
    false_positives = "Unsigned internal tooling, scripts, and freshly built or unpackaged software making outbound connections"
    references = "reports/sliver/source-analysis.md, public-rules/comparisons/sliver/sliver_process_behavior_cluster.md"
    validation_status = "needs_validation"
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/sliver/detection-review.md"
    source_comparison = "accepted_as_compensating_rule_from_unvalidated_proposal"
  events:
    $p.metadata.event_type = "PROCESS_LAUNCH"
    $p.principal.hostname = $host
    $p.target.process.product_specific_process_id = $pid
    $p.target.process.file.signature_info.verification_status != "VERIFIED"

    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.hostname = $host
    $n.principal.process.product_specific_process_id = $pid
    $n.network.direction = "OUTBOUND"
    $n.target.ip = $destination
  match: $host, $pid, $destination over 15m
  outcome:
    $connections = count($n.metadata.id)
  condition: $p and $n and $connections >= 2
}
```

- Re-comparison outcome: the current canonical rule set closes the branch the proposal targeted, within declared telemetry. Remaining limits are the accepted gaps in `reviews/sliver/detection-review.md`.
