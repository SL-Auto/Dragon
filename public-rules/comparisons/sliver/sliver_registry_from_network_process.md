# Public-rule comparison: sliver_registry_from_network_process

## Identity and independence gate

- Internal tool: `sliver`
- Internal canonical rule: `detections/sliver/yaral/sliver_registry_from_network_process.yaral`
- Internal SHA-256: `9985462cab2ae7c6771504d3ad3a03b219c47e96dca66a7a1a17cf0d17458210`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-018`
- Scope mapping rationale: procedure, ordered behavior, security effect, platform and telemetry; names and syntax were not mapping criteria.

Public candidate:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/persistence_registry_uncommon.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/persistence_registry_uncommon.toml) - SHA-256 `7a23c48df85ce80470a39bc43c0a4aded205b3d26fddbbc6c9772242baf8121e`

## Procedure and detection-branch matrix

| Procedure branch / effect | Ours | Public | Primary signal and strength | Compensating signal | Conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Process/session prerequisite | Partial process or identity context | Adjacent behavior only | Stable process/session entity - moderate | signer, first-seen and host-role context | complementary | Internal `PROC-018` inventory; cited candidate. |
| network-active process mutates registry state | Principal event family covered | Overlapping behavior under candidate-specific assumptions | network-active process writes a sensitive persistence or security-control key - strong | ordered child/file/network/state effect - moderate | complementary | Security effect is closer to procedure than a tool name. |
| Result, recurrence or cleanup | Partial or absent | Partial or outside scope | Verified resulting state - strong | subsequent access, transfer, deletion or authentication - moderate | different_scope | Neither rule closes every downstream branch. |

## Missing detection branches

- Missing from ours: Any registry mutation is too broad; security-sensitive keys, before/after value, persistence effect and process entity join are missing.
- Missing from public: The public candidate does not cover complete Sliver procedure ordering, the internal process-to-effect correlation, or tool-name-independent downstream confirmation.
- Missing from both: activity split across processes/hosts, low-and-slow execution, encrypted application content, telemetry outages, and reliable confirmation of operator intent.

## Detection edge cases and blind spots

Process identifiers can be reused and differ across sensors; prefer a sensor-issued process entity ID when available. NAT, proxies, resolver infrastructure, delayed ingestion, clock skew and partial endpoint visibility can break ordering. Legitimate software deployment, remote support, browsers, proxies, backup, monitoring and administration overlap with individual primitives. Baselines should raise or lower confidence without excluding the sensitive effect. Distributed and low-rate activity needs longer-lived entity analytics rather than simply expanding every correlation window.

## Signal-quality assessment

| Signal | Strength | Used by | Reason | Fragility |
| --- | --- | --- | --- | --- |
| network-active process writes a sensitive persistence or security-control key | strong | proposed refinement | Close to the security effect and behavior-based. | Requires stable entity joins and declared telemetry. |
| Process-attributed egress | moderate | ours | Valuable causal context but common alone. | Proxying and sensor gaps reduce attribution. |
| Image, argument, port or default name | weak | some public logic | Useful enrichment, not durable intent. | Mutable and common in benign workloads. |

## Public-rule weaknesses

The candidate supplies useful behaviorally relevant telemetry but not the whole Sliver procedure. Backend assumptions and fixed thresholds are not tenant validation; its predicates must not be copied blindly.

## Internal-rule weaknesses

Any registry mutation is too broad; security-sensitive keys, before/after value, persistence effect and process entity join are missing. Broad joins risk benign collisions; narrow windows and same-process assumptions risk false negatives during delayed, delegated or distributed behavior.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/sliver/detection-review.md`.
- Prior state: this trail still read `deferred_pending_rule_improvement_run`, although the 2026-08-16 backlog resolution (REVIEW-010 to REVIEW-014) had already acted on the proposal; this pass re-reviews that action and records the terminal decision.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - The narrow rule restricts writes to persistence and security-control keys (Run/RunOnce, Services, Winlogon, IFEO, Terminal Server) by an egressing PID.
  - Removed the proposal's `event_timestamp.seconds <=` ordering; bounded co-occurrence in the match window is kept (REVIEW-010).
  - Adopted as an additional narrow rule beside the broad base rule, not as a replacement, so procedures without the narrow sub-case keep coverage (REVIEW-012).
- Canonical result: `detections/sliver/yaral/sliver_registry_from_network_process.yaral`, SHA-256 `4e9f074d85e05c9c6e2a2e332d6738c60c045900bb29ce0b668e759cd1466173`.
- Canonical result: `detections/sliver/yaral/sliver_registry_persistence_key_from_network_process.yaral`, SHA-256 `2d053e0843ca8ca38820e0959ab3914f7753a5cd718bf0ef9d04e1a9f124e736`.
- Regeneration: coverage, telemetry, `telemetry/MASTER.md`, five translations and dependency hashes were regenerated on 2026-08-16 when the rule was adopted; re-verified present and hash-consistent on 2026-11-21.

## Unmatched scope

The candidate does not cover all of `PROC-018`. No global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: Any registry mutation is too broad; security-sensitive keys, before/after value, persistence effect and process entity join are missing.
- Required telemetry: stable process/session entity, actor, host, event time, action/result and procedure-specific file/network/state fields.
- Validation status: `unvalidated_proposal`

```yaral
rule sliver_registry_from_network_process_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-018"
    source_comparison = "unvalidated_proposal"
  events:
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.process.pid = $pid
    $n.network.direction = "OUTBOUND"
    $r.metadata.event_type = "REGISTRY_MODIFICATION"
    $r.principal.process.pid = $pid
    $r.target.registry.registry_key = /(?i)\\(Run|RunOnce|Services|Winlogon|Image File Execution Options|Terminal Server)\\?/
  match:
    $pid over 15m
  condition:
    $n and $r
}
```

The proposal uses concrete telemetry semantics but does not prove tool identity. It remains limited by collection health, process-entity fidelity, enrichment quality and activity outside the window. If accepted or modified, complete the full downstream workflow; if rejected, preserve the rationale without changing canonical logic.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/windows/persistence_registry_uncommon.toml` changed between 7e91c15 and 9d792a8; re-read on 2026-11-21: the candidate added further uncommon persistence paths (Terminal Server add-ins, accessibility ATs, TelemetryController, RDP client ClxDllPath and add-ins). That widens its `public_stronger` uncommon-key branch above. Our same-process egress correlation and the adopted rule's key set are unaffected.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Egressing process writes a persistence key | covered by `sliver_registry_persistence_key_from_network_process` | `persistence_registry_uncommon.toml`: changes to a curated list of uncommon persistence registry paths | persistence key plus same-PID egress - strong | uncommon-key list - moderate | complementary |
| Other registry mutation by an egressing process | covered by base rule | not covered | any registry write plus egress - weak | none | ours_stronger |
| Uncommon persistence keys outside our list | not covered | covered | extended key list - moderate | none | public_stronger |

- Current canonical YARA-L `detections/sliver/yaral/sliver_registry_from_network_process.yaral` (`experimental` / `needs_validation`):

```yaral
rule sliver_registry_from_network_process {
  meta:
    author = "Detection Research Agent"
    description = "Registry mutation by a process with outbound network activity"
    date = "2026-08-15"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "Links host configuration change to remote channel"
    procedure_ids = "PROC-018"
    log_source_prerequisites = "Registry mutation and network UDM with stable PID"
    false_positives = "Installers, management, security software"
    references = "reports/sliver/source-analysis.md"
    validation_status = "needs_validation"
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/sliver/detection-review.md"
  events:
    $r.metadata.event_type = "REGISTRY_MODIFICATION"
    $r.principal.hostname = $host
    $r.principal.process.product_specific_process_id = $pid

    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.network.direction = "OUTBOUND"
    $n.principal.hostname = $host
    $n.principal.process.product_specific_process_id = $pid
  match: $host, $pid over 10m
  condition: $r and $n
}
```

- Current canonical YARA-L `detections/sliver/yaral/sliver_registry_persistence_key_from_network_process.yaral` (`experimental` / `needs_validation`):

```yaral
rule sliver_registry_persistence_key_from_network_process {
  meta:
    author = "Detection Research Agent"
    description = "A network-active process writes a registry key commonly used for persistence or security-control tampering"
    date = "2026-08-16"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Restricting the target key to Run/RunOnce/Services/Winlogon/Image File Execution Options/Terminal Server paths converts the unusably broad any-mutation predicate into a precision signal tied to the security effect; the original broad rule is retained to preserve discovery-oriented and non-persistence write coverage"
    procedure_ids = "PROC-018"
    log_source_prerequisites = "Registry mutation telemetry with full key path, plus process-attributed network telemetry sharing a stable process entity"
    false_positives = "Installers, endpoint management, and security software that legitimately write persistence-adjacent keys"
    references = "reports/sliver/source-analysis.md, public-rules/comparisons/sliver/sliver_registry_from_network_process.md"
    validation_status = "needs_validation"
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/sliver/detection-review.md"
    source_comparison = "accepted_as_compensating_rule_from_unvalidated_proposal"
  events:
    $r.metadata.event_type = "REGISTRY_MODIFICATION"
    $r.principal.hostname = $host
    $r.principal.process.product_specific_process_id = $pid
    re.regex($r.target.registry.registry_key, `(?i)\\(run|runonce|services|winlogon|image file execution options|terminal server)\\?`)

    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.network.direction = "OUTBOUND"
    $n.principal.hostname = $host
    $n.principal.process.product_specific_process_id = $pid
  match: $host, $pid over 15m
  condition: $r and $n
}
```

- Re-comparison outcome: the current canonical rule set closes the branch the proposal targeted, within declared telemetry. Remaining limits are the accepted gaps in `reviews/sliver/detection-review.md`.
