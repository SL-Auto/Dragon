# Public-rule comparison: sliver_listener_with_egress

## Identity and independence gate

- Internal tool: `sliver`
- Internal canonical rule: `detections/sliver/yaral/sliver_listener_with_egress.yaral`
- Internal SHA-256: `ec9389fe0c604f0f67a767c4038ab7bde6405c2d7f0cb42789fe17b31ceba101`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-005,PROC-021`
- Scope mapping rationale: procedure, ordered behavior, security effect, platform and telemetry; names and syntax were not mapping criteria.

Public candidate:
- [`public-rules/snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/port_proxy_forwarding_T1090_cisa_report.yaral`](../../snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/port_proxy_forwarding_T1090_cisa_report.yaral) - SHA-256 `65d283ba8edead9233016571a5ec70310679d7ea31689016379b1283eb42d522`

## Procedure and detection-branch matrix

| Procedure branch / effect | Ours | Public | Primary signal and strength | Compensating signal | Conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Process/session prerequisite | Partial process or identity context | Adjacent behavior only | Stable process/session entity - moderate | signer, first-seen and host-role context | complementary | Internal `PROC-005,PROC-021` inventory; cited candidate. |
| one process accepts inbound traffic and establishes outbound transport | Principal event family covered | Overlapping behavior under candidate-specific assumptions | unapproved process accepts inbound and forwards to a first-seen destination - strong | ordered child/file/network/state effect - moderate | complementary | Security effect is closer to procedure than a tool name. |
| Result, recurrence or cleanup | Partial or absent | Partial or outside scope | Verified resulting state - strong | subsequent access, transfer, deletion or authentication - moderate | different_scope | Neither rule closes every downstream branch. |

## Missing detection branches

- Missing from ours: Legitimate proxies share this shape; listener role, destination novelty, connection acceptance and byte direction are absent.
- Missing from public: The public candidate does not cover complete Sliver procedure ordering, the internal process-to-effect correlation, or tool-name-independent downstream confirmation.
- Missing from both: activity split across processes/hosts, low-and-slow execution, encrypted application content, telemetry outages, and reliable confirmation of operator intent.

## Detection edge cases and blind spots

Process identifiers can be reused and differ across sensors; prefer a sensor-issued process entity ID when available. NAT, proxies, resolver infrastructure, delayed ingestion, clock skew and partial endpoint visibility can break ordering. Legitimate software deployment, remote support, browsers, proxies, backup, monitoring and administration overlap with individual primitives. Baselines should raise or lower confidence without excluding the sensitive effect. Distributed and low-rate activity needs longer-lived entity analytics rather than simply expanding every correlation window.

## Signal-quality assessment

| Signal | Strength | Used by | Reason | Fragility |
| --- | --- | --- | --- | --- |
| unapproved process accepts inbound and forwards to a first-seen destination | strong | proposed refinement | Close to the security effect and behavior-based. | Requires stable entity joins and declared telemetry. |
| Process-attributed egress | moderate | ours | Valuable causal context but common alone. | Proxying and sensor gaps reduce attribution. |
| Image, argument, port or default name | weak | some public logic | Useful enrichment, not durable intent. | Mutable and common in benign workloads. |

## Public-rule weaknesses

The candidate supplies useful behaviorally relevant telemetry but not the whole Sliver procedure. Backend assumptions and fixed thresholds are not tenant validation; its predicates must not be copied blindly.

## Internal-rule weaknesses

Legitimate proxies share this shape; listener role, destination novelty, connection acceptance and byte direction are absent. Broad joins risk benign collisions; narrow windows and same-process assumptions risk false negatives during delayed, delegated or distributed behavior.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/sliver/detection-review.md`.
- Prior state: this trail still read `deferred_pending_rule_improvement_run`, although the 2026-08-16 backlog resolution (REVIEW-010 to REVIEW-014) had already acted on the proposal; this pass re-reviews that action and records the terminal decision.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - The narrow rule requires one PID to accept an inbound connection and open an outbound connection to a different peer within 10 minutes.
  - Dropped the proposal's hard destination-prevalence requirement, which is optional enrichment in `telemetry/sliver.md` (REVIEW-011).
  - Adopted as an additional narrow rule beside the broad base rule, not as a replacement, so procedures without the narrow sub-case keep coverage (REVIEW-012).
  - Re-review: the rule name says "novel", but novelty is not enforced; this is recorded as an accepted gap (REVIEW-017).
- Canonical result: `detections/sliver/yaral/sliver_listener_with_egress.yaral`, SHA-256 `c9d97ddc6f775b766b84294e250406f4cd4ea62043a8e169f19f646d977f580e`.
- Canonical result: `detections/sliver/yaral/sliver_relay_to_novel_destination.yaral`, SHA-256 `b5c6853282df25f3d69d8dd843e9c3bc33e11e684c4779c83a230090b4f9c688`.
- Regeneration: coverage, telemetry, `telemetry/MASTER.md`, five translations and dependency hashes were regenerated on 2026-08-16 when the rule was adopted; re-verified present and hash-consistent on 2026-11-21.

## Unmatched scope

The candidate does not cover all of `PROC-005,PROC-021`. No global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: Legitimate proxies share this shape; listener role, destination novelty, connection acceptance and byte direction are absent.
- Required telemetry: stable process/session entity, actor, host, event time, action/result and procedure-specific file/network/state fields.
- Validation status: `unvalidated_proposal`

```yaral
rule sliver_listener_with_egress_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-005,PROC-021"
    source_comparison = "unvalidated_proposal"
  events:
    $l.metadata.event_type = "NETWORK_CONNECTION"
    $l.principal.process.pid = $pid
    $l.principal.hostname = $host
    $l.network.direction = "INBOUND"
    $l.security_result.action = "ALLOW"
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.process.pid = $pid
    $n.principal.hostname = $host
    $n.network.direction = "OUTBOUND"
    $n.target.ip = $destination
    $n.target.resource.attribute.labels["destination_prevalence"] = "rare"
  match:
    $host, $pid over 10m
  condition:
    $l and $n
}
```

The proposal uses concrete telemetry semantics but does not prove tool identity. It remains limited by collection health, process-entity fidelity, enrichment quality and activity outside the window. If accepted or modified, complete the full downstream workflow; if rejected, preserve the rationale without changing canonical logic.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/community/microsoft/windows/port_proxy_forwarding_T1090_cisa_report.yaral` differs between 234e922 and dbc9beb only in line endings (snapshot path moved where applicable); content is identical.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| One process accepts inbound and relays to a different peer | covered by `sliver_relay_to_novel_destination` | `port_proxy_forwarding_T1090_cisa_report.yaral`: netsh portproxy configuration | same-PID inbound plus outbound to a different peer - strong | base listener rule - moderate | complementary |
| Dormant pivot listener with no accepted peer | covered by base rule | not covered | process LISTEN plus egress - moderate | none | ours_stronger |
| OS-native port proxy (portproxy registry or netsh) | not targeted | covered | portproxy configuration - strong | none | different_scope |

- Current canonical YARA-L `detections/sliver/yaral/sliver_listener_with_egress.yaral` (`experimental` / `needs_validation`):

```yaral
rule sliver_listener_with_egress {
  meta:
    author = "Detection Research Agent"
    description = "One process both listens and makes outbound connections"
    date = "2026-08-15"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Captures pivot and relay fan-out"
    procedure_ids = "PROC-005,PROC-021"
    log_source_prerequisites = "EDR socket listen and process network events with stable PID"
    false_positives = "Proxies, VPN, developer and server software"
    references = "reports/sliver/source-analysis.md"
    validation_status = "needs_validation"
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/sliver/detection-review.md"
  events:
    $l.metadata.event_type = "NETWORK_CONNECTION"
    $l.network.direction = "LISTEN"
    $l.principal.hostname = $host
    $l.principal.process.product_specific_process_id = $pid

    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.network.direction = "OUTBOUND"
    $n.principal.hostname = $host
    $n.principal.process.product_specific_process_id = $pid
  match: $host, $pid over 15m
  condition: $l and $n
}
```

- Current canonical YARA-L `detections/sliver/yaral/sliver_relay_to_novel_destination.yaral` (`experimental` / `needs_validation`):

```yaral
rule sliver_relay_to_novel_destination {
  meta:
    author = "Detection Research Agent"
    description = "A process that accepted an inbound connection also makes an outbound connection to a distinct destination in the same window"
    date = "2026-08-16"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Requiring an accepted inbound connection, not merely a bound listener, paired with a distinct outbound destination is closer to the observable relay/forwarding effect than listen-plus-any-egress; compensates for the broad listener rule where legitimate proxies share the bare listen+egress shape"
    procedure_ids = "PROC-005,PROC-021"
    log_source_prerequisites = "EDR/firewall inbound-accept and outbound-connect telemetry sharing a stable process entity, with source and destination IP"
    false_positives = "Legitimate reverse proxies, load balancers, VPN concentrators, and remote-support/relay software"
    references = "reports/sliver/source-analysis.md, public-rules/comparisons/sliver/sliver_listener_with_egress.md"
    validation_status = "needs_validation"
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/sliver/detection-review.md"
    source_comparison = "accepted_as_compensating_rule_from_unvalidated_proposal"
  events:
    $in.metadata.event_type = "NETWORK_CONNECTION"
    $in.network.direction = "INBOUND"
    $in.principal.hostname = $host
    $in.principal.process.product_specific_process_id = $pid
    $in.principal.ip = $inbound_source

    $out.metadata.event_type = "NETWORK_CONNECTION"
    $out.network.direction = "OUTBOUND"
    $out.principal.hostname = $host
    $out.principal.process.product_specific_process_id = $pid
    $out.target.ip = $outbound_destination
  match: $host, $pid over 10m
  condition: $in and $out and $inbound_source != $outbound_destination
}
```

- Re-comparison outcome: the current canonical rule set closes the branch the proposal targeted, within declared telemetry. Remaining limits are the accepted gaps in `reviews/sliver/detection-review.md`.
