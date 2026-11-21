# Public-rule comparison: sliver_screen_capture_process_egress

## Identity and independence gate

- Internal tool: `sliver`
- Internal canonical rule: `detections/sliver/yaral/sliver_screen_capture_process_egress.yaral`
- Internal SHA-256: `c3dd246e5bb8d3ed2b32e7f2e5f1c14ad3f84872439ce86c011fd4962f2b3b00`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-014`
- Scope mapping rationale: procedure, ordered behavior, security effect, platform and telemetry; names and syntax were not mapping criteria.

Public candidate:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/linux/collection_potential_video_recording_or_screenshot_activity.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/linux/collection_potential_video_recording_or_screenshot_activity.toml) - SHA-256 `9e2df48178e666f66ff2441e483b7291a532b08d6e8765d4db5b5c4e8a75d814`

## Procedure and detection-branch matrix

| Procedure branch / effect | Ours | Public | Primary signal and strength | Compensating signal | Conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Process/session prerequisite | Partial process or identity context | Adjacent behavior only | Stable process/session entity - moderate | signer, first-seen and host-role context | complementary | Internal `PROC-014` inventory; cited candidate. |
| screen-capture API activity is followed by same-process egress | Principal event family covered | Overlapping behavior under candidate-specific assumptions | screen-capture event joined by process entity to external transfer - strong | ordered child/file/network/state effect - moderate | complementary | Security effect is closer to procedure than a tool name. |
| Result, recurrence or cleanup | Partial or absent | Partial or outside scope | Verified resulting state - strong | subsequent access, transfer, deletion or authentication - moderate | different_scope | Neither rule closes every downstream branch. |

## Missing detection branches

- Missing from ours: Capture telemetry is tenant-normalized and may not identify the captured desktop, result artifact, session or API provider.
- Missing from public: The public candidate does not cover complete Sliver procedure ordering, the internal process-to-effect correlation, or tool-name-independent downstream confirmation.
- Missing from both: activity split across processes/hosts, low-and-slow execution, encrypted application content, telemetry outages, and reliable confirmation of operator intent.

## Detection edge cases and blind spots

Process identifiers can be reused and differ across sensors; prefer a sensor-issued process entity ID when available. NAT, proxies, resolver infrastructure, delayed ingestion, clock skew and partial endpoint visibility can break ordering. Legitimate software deployment, remote support, browsers, proxies, backup, monitoring and administration overlap with individual primitives. Baselines should raise or lower confidence without excluding the sensitive effect. Distributed and low-rate activity needs longer-lived entity analytics rather than simply expanding every correlation window.

## Signal-quality assessment

| Signal | Strength | Used by | Reason | Fragility |
| --- | --- | --- | --- | --- |
| screen-capture event joined by process entity to external transfer | strong | proposed refinement | Close to the security effect and behavior-based. | Requires stable entity joins and declared telemetry. |
| Process-attributed egress | moderate | ours | Valuable causal context but common alone. | Proxying and sensor gaps reduce attribution. |
| Image, argument, port or default name | weak | some public logic | Useful enrichment, not durable intent. | Mutable and common in benign workloads. |

## Public-rule weaknesses

The candidate supplies useful behaviorally relevant telemetry but not the whole Sliver procedure. Backend assumptions and fixed thresholds are not tenant validation; its predicates must not be copied blindly.

## Internal-rule weaknesses

Capture telemetry is tenant-normalized and may not identify the captured desktop, result artifact, session or API provider. Broad joins risk benign collisions; narrow windows and same-process assumptions risk false negatives during delayed, delegated or distributed behavior.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/sliver/detection-review.md`.
- Prior state: this trail still read `deferred_pending_rule_improvement_run`, although the 2026-08-16 backlog resolution (REVIEW-010 to REVIEW-014) had already acted on the proposal; this pass re-reviews that action and records the terminal decision.
- Decision: `reject`.
- Reason: the proposal is not adopted:
  - The stated gap (captured desktop, session or API provider unknown) is an inherent telemetry limitation already recorded as `needs_validation`; the proposal added no field that resolves it (REVIEW-013).
  - It swapped one unverified vendor event-type guess for another and reintroduced strict ordering (REVIEW-010).
- Canonical result: no canonical logic changed; the proposed code is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration: none required; canonical logic is unchanged.

## Unmatched scope

The candidate does not cover all of `PROC-014`. No global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: Capture telemetry is tenant-normalized and may not identify the captured desktop, result artifact, session or API provider.
- Required telemetry: stable process/session entity, actor, host, event time, action/result and procedure-specific file/network/state fields.
- Validation status: `unvalidated_proposal`

```yaral
rule sliver_screen_capture_process_egress_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-014"
    source_comparison = "unvalidated_proposal"
  events:
    $c.metadata.product_event_type = /SCREEN_CAPTURE|DesktopDuplication|BitBlt/
    $c.principal.process.pid = $pid
    $c.principal.hostname = $host
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.process.pid = $pid
    $n.principal.hostname = $host
    $n.network.direction = "OUTBOUND"
    $c.metadata.event_timestamp.seconds <= $n.metadata.event_timestamp.seconds
  match:
    $host, $pid over 5m
  condition:
    $c and $n
}
```

The proposal uses concrete telemetry semantics but does not prove tool identity. It remains limited by collection health, process-entity fidelity, enrichment quality and activity outside the window. If accepted or modified, complete the full downstream workflow; if rejected, preserve the rationale without changing canonical logic.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/linux/collection_potential_video_recording_or_screenshot_activity.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Screen-capture activity joined to same-process egress | covered (vendor capture event plus same-PID egress) | `collection_potential_video_recording_or_screenshot_activity.toml`: Linux screenshot/recording utilities from an uncommon parent | capture event plus egress - moderate | Linux utility execution - weak | different_scope |

- Re-comparison outcome: canonical logic is unchanged; the comparison conclusions above stand against the re-pinned candidate.
