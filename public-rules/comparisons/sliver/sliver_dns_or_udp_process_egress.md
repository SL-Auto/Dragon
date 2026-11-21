# Public-rule comparison: sliver_dns_or_udp_process_egress

## Identity and independence gate

- Internal tool: `sliver`
- Internal canonical rule: `detections/sliver/yaral/sliver_dns_or_udp_process_egress.yaral`
- Internal SHA-256: `b4971ecd76cbd288a53394c27b79a873922766adcf60d96efa457325d2c1ff95`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-004`
- Scope mapping rationale: procedure, ordered behavior, security effect, platform and telemetry; names and syntax were not mapping criteria.

Public candidate:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/ml/command_and_control_ml_dns_tunneling.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/ml/command_and_control_ml_dns_tunneling.toml) - SHA-256 `eaa66978039f203084f832a39b78947d13becee680f3ecbfd6bb21bedbd782ea`

## Procedure and detection-branch matrix

| Procedure branch / effect | Ours | Public | Primary signal and strength | Compensating signal | Conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Process/session prerequisite | Partial process or identity context | Adjacent behavior only | Stable process/session entity - moderate | signer, first-seen and host-role context | complementary | Internal `PROC-004` inventory; cited candidate. |
| DNS or UDP transport with repeated process-attributed egress | Principal event family covered | Overlapping behavior under candidate-specific assumptions | first-seen process-to-UDP destination with periodic recurrence - strong | ordered child/file/network/state effect - moderate | complementary | Security effect is closer to procedure than a tool name. |
| Result, recurrence or cleanup | Partial or absent | Partial or outside scope | Verified resulting state - strong | subsequent access, transfer, deletion or authentication - moderate | different_scope | Neither rule closes every downstream branch. |

## Missing detection branches

- Missing from ours: A volume threshold misses low-rate sessions and does not distinguish resolver DNS, direct DNS, WireGuard-like UDP, or destination novelty.
- Missing from public: The public candidate does not cover complete Sliver procedure ordering, the internal process-to-effect correlation, or tool-name-independent downstream confirmation.
- Missing from both: activity split across processes/hosts, low-and-slow execution, encrypted application content, telemetry outages, and reliable confirmation of operator intent.

## Detection edge cases and blind spots

Process identifiers can be reused and differ across sensors; prefer a sensor-issued process entity ID when available. NAT, proxies, resolver infrastructure, delayed ingestion, clock skew and partial endpoint visibility can break ordering. Legitimate software deployment, remote support, browsers, proxies, backup, monitoring and administration overlap with individual primitives. Baselines should raise or lower confidence without excluding the sensitive effect. Distributed and low-rate activity needs longer-lived entity analytics rather than simply expanding every correlation window.

## Signal-quality assessment

| Signal | Strength | Used by | Reason | Fragility |
| --- | --- | --- | --- | --- |
| first-seen process-to-UDP destination with periodic recurrence | strong | proposed refinement | Close to the security effect and behavior-based. | Requires stable entity joins and declared telemetry. |
| Process-attributed egress | moderate | ours | Valuable causal context but common alone. | Proxying and sensor gaps reduce attribution. |
| Image, argument, port or default name | weak | some public logic | Useful enrichment, not durable intent. | Mutable and common in benign workloads. |

## Public-rule weaknesses

The candidate supplies useful behaviorally relevant telemetry but not the whole Sliver procedure. Backend assumptions and fixed thresholds are not tenant validation; its predicates must not be copied blindly.

## Internal-rule weaknesses

A volume threshold misses low-rate sessions and does not distinguish resolver DNS, direct DNS, WireGuard-like UDP, or destination novelty. Broad joins risk benign collisions; narrow windows and same-process assumptions risk false negatives during delayed, delegated or distributed behavior.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/sliver/detection-review.md`.
- Prior state: this trail still read `deferred_pending_rule_improvement_run`, although the 2026-08-16 backlog resolution (REVIEW-010 to REVIEW-014) had already acted on the proposal; this pass re-reviews that action and records the terminal decision.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - Recurrence is measured per host, PID, destination and port as at least 6 events spread over at least 4 distinct minutes in 30 minutes, instead of first-seen prevalence.
  - Dropped the proposal's hard destination-prevalence requirement, which is optional enrichment in `telemetry/sliver.md` (REVIEW-011).
  - Adopted as an additional narrow rule beside the broad base rule, not as a replacement, so procedures without the narrow sub-case keep coverage (REVIEW-012).
- Canonical result: `detections/sliver/yaral/sliver_dns_or_udp_process_egress.yaral`, SHA-256 `b4971ecd76cbd288a53394c27b79a873922766adcf60d96efa457325d2c1ff95`.
- Canonical result: `detections/sliver/yaral/sliver_low_and_slow_udp_beacon.yaral`, SHA-256 `67a99ecaeb3c4a2d9702b5f5a8a986a3b86fd35fe2822c2bef614b0ed4974e4f`.
- Regeneration: coverage, telemetry, `telemetry/MASTER.md`, five translations and dependency hashes were regenerated on 2026-08-16 when the rule was adopted; re-verified present and hash-consistent on 2026-11-21.

## Unmatched scope

The candidate does not cover all of `PROC-004`. No global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: A volume threshold misses low-rate sessions and does not distinguish resolver DNS, direct DNS, WireGuard-like UDP, or destination novelty.
- Required telemetry: stable process/session entity, actor, host, event time, action/result and procedure-specific file/network/state fields.
- Validation status: `unvalidated_proposal`

```yaral
rule sliver_dns_or_udp_process_egress_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-004"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.principal.process.pid = $pid
    $e.network.ip_protocol = "UDP"
    $e.network.direction = "OUTBOUND"
    $e.target.ip = $destination
    $e.target.port = $port
    $e.target.resource.attribute.labels["destination_prevalence"] = "rare"
  match:
    $pid, $destination, $port over 30m
  outcome:
    $connections = count($e.metadata.id)
  condition:
    $e and $connections >= 6
}
```

The proposal uses concrete telemetry semantics but does not prove tool identity. It remains limited by collection health, process-entity fidelity, enrichment quality and activity outside the window. If accepted or modified, complete the full downstream workflow; if rejected, preserve the rationale without changing canonical logic.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/ml/command_and_control_ml_dns_tunneling.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Process-attributed DNS/UDP transport | covered by base rule | `command_and_control_ml_dns_tunneling.toml`: ML job on unusually many DNS queries for one top-level domain | process-attributed UDP egress - moderate | ML DNS anomaly - moderate | complementary |
| Low-and-slow periodic UDP to one destination | covered by `sliver_low_and_slow_udp_beacon` | covered only if query volume to one TLD is anomalous | minute-spread recurrence per destination - strong | none | complementary |
| High-volume DNS tunnelling to one domain | covered only when process-attributed | covered by the ML job without process attribution | per-domain query volume - moderate | none | complementary |

- Current canonical YARA-L `detections/sliver/yaral/sliver_dns_or_udp_process_egress.yaral` (`experimental` / `needs_validation`):

```yaral
rule sliver_dns_or_udp_process_egress {
  meta:
    author = "Detection Research Agent"
    description = "High-volume DNS or UDP from one process"
    date = "2026-08-15"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "Covers DNS and tunnel transports without mutable indicators"
    procedure_ids = "PROC-004"
    log_source_prerequisites = "Process-attributed DNS or UDP network telemetry"
    false_positives = "Resolvers, browsers, VPN clients"
    references = "reports/sliver/source-analysis.md"
    validation_status = "needs_validation"
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/sliver/detection-review.md"
  events:
    $e.principal.hostname = $host
    $e.principal.process.file.full_path = $proc ($e.metadata.event_type = "NETWORK_DNS" or
    $e.network.ip_protocol = "UDP")
  match: $host, $proc over 10m
  outcome: $count = count($e.metadata.id)
  condition: $e and $count >= 20
}
```

- Current canonical YARA-L `detections/sliver/yaral/sliver_low_and_slow_udp_beacon.yaral` (`experimental` / `needs_validation`):

```yaral
rule sliver_low_and_slow_udp_beacon {
  meta:
    author = "Detection Research Agent"
    description = "One process makes low-volume, time-spread, repeated DNS or UDP connections to the same destination and port"
    date = "2026-08-16"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "Per-destination recurrence with a time-spread requirement covers low-and-slow DNS/WireGuard-style channels that a flat 20-events-per-10-minutes burst threshold misses"
    procedure_ids = "PROC-004"
    log_source_prerequisites = "Process-attributed DNS or UDP network telemetry with stable destination and port"
    false_positives = "DNS resolvers, VPN/WireGuard clients, monitoring agents, chat/voice UDP applications"
    references = "reports/sliver/source-analysis.md, public-rules/comparisons/sliver/sliver_dns_or_udp_process_egress.md"
    validation_status = "needs_validation"
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/sliver/detection-review.md"
    source_comparison = "accepted_as_compensating_rule_from_unvalidated_proposal"
  events:
    $e.principal.hostname = $host
    $e.principal.process.product_specific_process_id = $pid
    $e.target.ip = $destination
    $e.target.port = $port
    ($e.metadata.event_type = "NETWORK_DNS" or $e.network.ip_protocol = "UDP")
  match: $host, $pid, $destination, $port over 30m
  outcome:
    $connections = count($e.metadata.id)
    $active_minutes = count_distinct(timestamp.get_minute($e.metadata.event_timestamp.seconds))
  condition: $e and $connections >= 6 and $active_minutes >= 4
}
```

- Re-comparison outcome: the current canonical rule set closes the branch the proposal targeted, within declared telemetry. Remaining limits are the accepted gaps in `reviews/sliver/detection-review.md`.
