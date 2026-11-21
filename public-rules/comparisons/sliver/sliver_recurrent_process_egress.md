# Public-rule comparison: sliver_recurrent_process_egress

## Identity and independence gate

- Internal tool: `sliver`
- Internal canonical rule: `detections/sliver/yaral/sliver_recurrent_process_egress.yaral`
- Internal SHA-256: `a4c5b1dc30ec8096f016a997217362eba7b4b5eb2ad87f916f776b53cc6bc9be`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-002,PROC-003`
- Scope mapping rationale: procedure, ordered behavior, security effect, platform and telemetry; names and syntax were not mapping criteria.

Public candidate:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/beaconing/command_and_control_beaconing.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/beaconing/command_and_control_beaconing.toml) - SHA-256 `15dcc199f4d6f4c857491e708ee86dca4969214ba73533c85c30e39e5b038c0c`

## Procedure and detection-branch matrix

| Procedure branch / effect | Ours | Public | Primary signal and strength | Compensating signal | Conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Process/session prerequisite | Partial process or identity context | Adjacent behavior only | Stable process/session entity - moderate | signer, first-seen and host-role context | complementary | Internal `PROC-002,PROC-003` inventory; cited candidate. |
| one process repeatedly communicates outbound | Principal event family covered | Overlapping behavior under candidate-specific assumptions | low-jitter recurrent egress to a rare destination by one process - strong | ordered child/file/network/state effect - moderate | complementary | Security effect is closer to procedure than a tool name. |
| Result, recurrence or cleanup | Partial or absent | Partial or outside scope | Verified resulting state - strong | subsequent access, transfer, deletion or authentication - moderate | different_scope | Neither rule closes every downstream branch. |

## Missing detection branches

- Missing from ours: Five connections is a weak count, missing periodicity, destination stability, rarity, long-lived flow and proxy visibility.
- Missing from public: The public candidate does not cover complete Sliver procedure ordering, the internal process-to-effect correlation, or tool-name-independent downstream confirmation.
- Missing from both: activity split across processes/hosts, low-and-slow execution, encrypted application content, telemetry outages, and reliable confirmation of operator intent.

## Detection edge cases and blind spots

Process identifiers can be reused and differ across sensors; prefer a sensor-issued process entity ID when available. NAT, proxies, resolver infrastructure, delayed ingestion, clock skew and partial endpoint visibility can break ordering. Legitimate software deployment, remote support, browsers, proxies, backup, monitoring and administration overlap with individual primitives. Baselines should raise or lower confidence without excluding the sensitive effect. Distributed and low-rate activity needs longer-lived entity analytics rather than simply expanding every correlation window.

## Signal-quality assessment

| Signal | Strength | Used by | Reason | Fragility |
| --- | --- | --- | --- | --- |
| low-jitter recurrent egress to a rare destination by one process | strong | proposed refinement | Close to the security effect and behavior-based. | Requires stable entity joins and declared telemetry. |
| Process-attributed egress | moderate | ours | Valuable causal context but common alone. | Proxying and sensor gaps reduce attribution. |
| Image, argument, port or default name | weak | some public logic | Useful enrichment, not durable intent. | Mutable and common in benign workloads. |

## Public-rule weaknesses

The candidate supplies useful behaviorally relevant telemetry but not the whole Sliver procedure. Backend assumptions and fixed thresholds are not tenant validation; its predicates must not be copied blindly.

## Internal-rule weaknesses

Five connections is a weak count, missing periodicity, destination stability, rarity, long-lived flow and proxy visibility. Broad joins risk benign collisions; narrow windows and same-process assumptions risk false negatives during delayed, delegated or distributed behavior.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/sliver/detection-review.md`.
- Prior state: this trail still read `deferred_pending_rule_improvement_run`, although the 2026-08-16 backlog resolution (REVIEW-010 to REVIEW-014) had already acted on the proposal; this pass re-reviews that action and records the terminal decision.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - Rewritten in place: grouped by host, PID and destination (not process image) and requiring at least 5 connections across at least 4 distinct minutes in 1 hour (REVIEW-003, REVIEW-014).
  - Dropped the proposal's hard destination-prevalence requirement, which is optional enrichment in `telemetry/sliver.md` (REVIEW-011).
- Canonical result: `detections/sliver/yaral/sliver_recurrent_process_egress.yaral`, SHA-256 `8ceeda0c19ed5b6fd4a4c0463fa38d65bff3ee64aae738aebed1c1333ce7d605`.
- Regeneration: coverage, telemetry, `telemetry/MASTER.md`, five translations and dependency hashes were regenerated on 2026-08-16 when the rule was adopted; re-verified present and hash-consistent on 2026-11-21.

## Unmatched scope

The candidate does not cover all of `PROC-002,PROC-003`. No global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: Five connections is a weak count, missing periodicity, destination stability, rarity, long-lived flow and proxy visibility.
- Required telemetry: stable process/session entity, actor, host, event time, action/result and procedure-specific file/network/state fields.
- Validation status: `unvalidated_proposal`

```yaral
rule sliver_recurrent_process_egress_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-002,PROC-003"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.principal.process.pid = $pid
    $e.network.direction = "OUTBOUND"
    $e.target.ip = $destination
    $e.target.resource.attribute.labels["destination_prevalence"] = "rare"
  match:
    $pid, $destination over 1h
  outcome:
    $connections = count($e.metadata.id)
    $active_minutes = count_distinct(timestamp.get_minute($e.metadata.event_timestamp.seconds))
  condition:
    $e and $connections >= 6 and $active_minutes >= 4
}
```

The proposal uses concrete telemetry semantics but does not prove tool identity. It remains limited by collection health, process-entity fidelity, enrichment quality and activity outside the window. If accepted or modified, complete the full downstream workflow; if rejected, preserve the rationale without changing canonical logic.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/integrations/beaconing/command_and_control_beaconing.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| One process repeatedly contacts one destination | covered (PID plus destination, minute spread) | `command_and_control_beaconing.toml`: beaconing-integration statistical model (`beacon_stats.is_beaconing`) | per-destination minute-spread recurrence - strong | integration beaconing score - moderate | complementary |
| Jittered or long-interval beaconing beyond 1 hour | not covered | covered by the integration's longer baselines | long-window periodicity - moderate | `sliver_low_and_slow_udp_beacon` for UDP - moderate | public_stronger |

- Current canonical YARA-L `detections/sliver/yaral/sliver_recurrent_process_egress.yaral` (`experimental` / `needs_validation`):

```yaral
rule sliver_recurrent_process_egress {
  meta:
    author = "Detection Research Agent"
    description = "One process entity repeatedly communicates outbound to the same destination, spread across multiple minutes"
    date = "2026-08-16"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "Adding per-destination grouping and a minute-spread requirement fixes the review-acknowledged weakness that a bare five-connections-per-image threshold with no destination dimension is satisfied by ordinary multi-site browsing and misses whether recurrence is against one stable destination"
    procedure_ids = "PROC-002,PROC-003"
    log_source_prerequisites = "Process-attributed network events with stable process entity and destination"
    false_positives = "Agents, updaters, browsers, monitoring"
    references = "reports/sliver/source-analysis.md, public-rules/comparisons/sliver/sliver_recurrent_process_egress.md"
    validation_status = "needs_validation"
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/sliver/detection-review.md"
    source_comparison = "modified_from_unvalidated_proposal"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.network.direction = "OUTBOUND"
    $e.principal.hostname = $host
    $e.principal.process.product_specific_process_id = $pid
    $e.target.ip = $destination
  match: $host, $pid, $destination over 1h
  outcome:
    $connections = count($e.metadata.id)
    $active_minutes = count_distinct(timestamp.get_minute($e.metadata.event_timestamp.seconds))
  condition: $e and $connections >= 5 and $active_minutes >= 4
}
```

- Re-comparison outcome: the current canonical rule set closes the branch the proposal targeted, within declared telemetry. Remaining limits are the accepted gaps in `reviews/sliver/detection-review.md`.
