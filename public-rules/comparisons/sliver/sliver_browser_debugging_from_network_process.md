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

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/sliver/detection-review.md`.
- Prior state: this trail still read `deferred_pending_rule_improvement_run`, although the 2026-08-16 backlog resolution (REVIEW-010 to REVIEW-014) had already acted on the proposal; this pass re-reviews that action and records the terminal decision.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - Rewritten in place: the browser child must both carry `--remote-debugging-(port|pipe)` and open a LISTEN socket, and its parent must egress, joined by host, parent PID and browser PID (REVIEW-014).
  - Removed the proposal's `event_timestamp.seconds <=` ordering; bounded co-occurrence in the match window is kept (REVIEW-010).
- Canonical result: `detections/sliver/yaral/sliver_browser_debugging_from_network_process.yaral`, SHA-256 `96dbc0b7bae8d43a067c6aa497fd5f4955e69ec881c3de9f6401451221f48b06`.
- Regeneration: coverage, telemetry, `telemetry/MASTER.md`, five translations and dependency hashes were regenerated on 2026-08-16 when the rule was adopted; re-verified present and hash-consistent on 2026-11-21.

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

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- All public candidates were re-pinned to the refreshed snapshots; no referenced candidate file changed content.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Network-active process launches a browser with a remote-debugging option | covered (command line plus child PID) | no credible counterpart in the pinned snapshots | debugging switch on a child of an egressing process - strong | child LISTEN socket - strong | ours_stronger |
| Debugging endpoint becomes reachable (local listener) | covered by the `$l` LISTEN event | not covered | LISTEN by browser PID - strong | none | ours_stronger |
| Session data read through the debugging protocol | not observable at the host layer | not covered | none | subsequent egress by the parent - moderate | different_scope |

- Current canonical YARA-L `detections/sliver/yaral/sliver_browser_debugging_from_network_process.yaral` (`experimental` / `needs_validation`):

```yaral
rule sliver_browser_debugging_from_network_process {
  meta:
    author = "Detection Research Agent"
    description = "Network process launches a browser child with remote debugging enabled and a debug listener is established"
    date = "2026-08-16"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Requires the debug-switch launch, an established local debug listener on the launched child, and continuing egress by the launching process; closes the prior gap where the join required neither a listener nor a distinct browser-child identity, and fixes a malformed multi-predicate line in the prior version"
    procedure_ids = "PROC-022"
    log_source_prerequisites = "Process command line plus parent network telemetry and child listen-socket telemetry"
    false_positives = "Developers, browser automation and testing frameworks that launch browsers with remote debugging"
    references = "reports/sliver/source-analysis.md, public-rules/comparisons/sliver/sliver_browser_debugging_from_network_process.md"
    validation_status = "needs_validation"
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/sliver/detection-review.md"
    source_comparison = "modified_from_unvalidated_proposal"
  events:
    $p.metadata.event_type = "PROCESS_LAUNCH"
    $p.principal.hostname = $host
    $p.principal.process.product_specific_process_id = $parent_pid
    $p.target.process.product_specific_process_id = $browser_pid
    re.regex($p.target.process.command_line, `(?i)--remote-debugging-(port|pipe)`)

    $l.metadata.event_type = "NETWORK_CONNECTION"
    $l.network.direction = "LISTEN"
    $l.principal.hostname = $host
    $l.principal.process.product_specific_process_id = $browser_pid

    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.network.direction = "OUTBOUND"
    $n.principal.hostname = $host
    $n.principal.process.product_specific_process_id = $parent_pid
  match: $host, $parent_pid, $browser_pid over 10m
  condition: $p and $l and $n
}
```

- Re-comparison outcome: the current canonical rule set closes the branch the proposal targeted, within declared telemetry. Remaining limits are the accepted gaps in `reviews/sliver/detection-review.md`.
