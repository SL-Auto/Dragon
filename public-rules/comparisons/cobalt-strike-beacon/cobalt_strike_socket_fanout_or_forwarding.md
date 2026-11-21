# Public-rule comparison: cobalt_strike_socket_fanout_or_forwarding

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_socket_fanout_or_forwarding.yaral`
- Internal SHA-256: `460c62b248514121434ee905ccd18767f08240fc77c0ef651f5b2ade21efb844`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-009`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/_deprecated/command_and_control_linux_chisel_server_activity.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/_deprecated/command_and_control_linux_chisel_server_activity.toml) - SHA-256 `9d206ceb9c9ae2b0931af8f4384a2696703ac4ce620e3d51a2af6f3b119163d2`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite and execution context | Process/entity context is retained | Candidate supplies a narrower implementation-specific context | Process attribution - moderate | identity/session baseline | complementary | Canonical rule and pinned candidate above. |
| SOCKS, forwarding, and pivot traffic through a single process | many distinct destinations from uncommon process | proxy/tunnel rules add simultaneous inbound/outbound, byte ratios, and protocol context | same process accepts inbound and creates outbound fan-out - strong | ordered downstream security effect | complementary | Procedure `CSB-009` and the cited public rule cover overlapping but non-identical observables. |
| Resulting security effect or artifact | Partially covered | Partially covered | result correlation - strong when present | host/user/time-bounded sequence | different_scope | Neither rule proves every procedure outcome. |

## Missing detection branches

- Missing from ours: relay topology: inbound connection followed by multiple outbound connections from same process.
- Missing from the public candidate: the complete tool-independent ordered procedure and all Beacon-supported implementation variants.
- Missing from both: reliable attribution to Cobalt Strike; these are behavioral detections and must not claim tool identity.

## Detection edge cases and blind spots

browsers and agents create high destination fan-out without forwarding. Partial collection, clock skew, event loss, and process or identity key reuse can also break correlations. Low-and-slow activity may fall outside fixed windows, while distributing steps across processes can defeat same-process joins. These are detection limitations, not operational guidance.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| same process accepts inbound and creates outbound fan-out | strong | ours | Close to the relevant security effect and less dependent on mutable names. | Depends on normalized process/entity fields and local baselines. |
| Candidate implementation indicator | moderate | public | Adds a concrete observable branch absent from ours. | Often tied to one implementation, field model, or default. |
| Name, path, or command fragment alone | weak | public where present | Useful only as context, not proof of the procedure. | Mutable and commonly overlaps administration. |

## Public-rule weaknesses

The candidate is useful as an independent compensating branch, but its narrower implementation assumptions do not cover the complete procedure. Any literal names, paths, command fragments, fixed thresholds, or product enrichments remain fragile until validated locally. It must not be copied blindly.

## Internal-rule weaknesses

The canonical rule has broader tool-independent intent, but relay topology: inbound connection followed by multiple outbound connections from same process. Its correlation also assumes consistent entity normalization and adequate collection across the declared window.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against source analysis, provider field semantics and `reviews/cobalt-strike-beacon/detection-review.md`.
- Prior state: the proposal was copied into canonical YARA-L on 2026-08-16 while this trail read `deferred_pending_rule_improvement_run`, a non-terminal state the workflow prohibits. It is re-decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real, but adversarial review found defects in the proposal as written; the adopted rule diverges as follows:
  - Joins on `product_specific_process_id` with host on every event, replacing the non-UDM `entity_id` (DR-20).
  - Enforced first-event-before-second ordering (DR-15).
  - Distinct-destination count moved to `outcome`.
- Canonical result: `detections/cobalt-strike-beacon/yaral/cobalt_strike_socket_fanout_or_forwarding_compensating_signal.yaral`, SHA-256 `0c20a1438e4bb0b750868e630545a3c15c21307c02b53553d7d8f1d9586d4787`. The original proposal is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration completed in the same run: detection review, coverage ledger, tool telemetry file, `telemetry/MASTER.md` counts, all five translations, translation review, dependency/manifest hashes, and the re-comparison below.
## Unmatched scope

The public candidate does not cover all branches in `CSB-009`. Conversely, the canonical rule is not evidence of Cobalt Strike attribution and may detect other tooling with equivalent effects.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: relay topology: inbound connection followed by multiple outbound connections from same process.
- Required telemetry: normalized `NETWORK_CONNECTION` plus the entity, enrichment, and correlation fields used below; collection health must be monitored.
- Validation status: `unvalidated_proposal`

```yaral
rule cobalt_strike_socket_fanout_or_forwarding_compensating_signal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    description = "Independent compensating signal proposed after public-rule comparison"
    procedure_ids = "CSB-009"
  events:
    $in.metadata.event_type = "NETWORK_CONNECTION"
        $in.principal.hostname = $host
        $in.network.direction = "INBOUND"
        $in.target.process.pid = $pid
        $out.metadata.event_type = "NETWORK_CONNECTION"
        $out.network.direction = "OUTBOUND"
        $out.principal.process.pid = $pid
        $out.target.ip = $destination
  match:
    $host, $pid over 15m
  condition:
    $in and $out and #destination >= 5
}
```

This proposal is deliberately not canonical. Thresholds, field availability, benign prevalence, and join stability require adversarial review. Remaining gaps include telemetry loss, cross-host clock skew, and variants that do not produce the proposed effect.

If accepted or modified, update the canonical rule in the same run and regenerate every required downstream artifact before marking the comparison complete.

## Re-comparison against revised canonical rule

- Revised rule SHA-256 `0c20a1438e4bb0b750868e630545a3c15c21307c02b53553d7d8f1d9586d4787`, compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- All public candidates were re-pinned to the refreshed snapshots with no content change in the referenced files.
- The pinned candidate lives under Elastic `_deprecated/` and is a weak comparator for this branch; a stronger public counterpart should be sought when this comparison is next refreshed. The candidate targets Linux Chisel server activity, not Beacon SOCKS forwarding; the pairing is weak.

| Procedure branch / observable effect | Revised ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Inbound accept then outbound fan-out by the same process | covered, ordered | `command_and_control_linux_chisel_server_activity.toml`: narrower implementation-specific context (original matrix); candidate not re-assessed beyond re-pinning | relay topology on one process - strong | base outbound fan-out - moderate | complementary | Revised canonical rule, re-pinned candidate, `reviews/cobalt-strike-beacon/detection-review.md`. |

- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule cobalt_strike_socket_fanout_or_forwarding_compensating_signal {
  meta:
    author = "Detection Research Agent"
    description = "Correlates an inbound connection to a process with that same process subsequently creating multiple distinct outbound connections, detecting the relay/forwarding topology that the base outbound-only fan-out rule cannot express."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "A process that accepts an inbound connection and then fans out to several distinct outbound destinations is a strong relay/pivot signal, though browsers and legitimate proxy/agent software can match."
    procedure_ids = "CSB-009"
    log_source_prerequisites = "Normalize NETWORK_CONNECTION for both inbound and outbound direction with a stable vendor process identifier (product_specific_process_id), joined on host and process within 15 minutes, inbound first."
    false_positives = "Browsers, approved proxies, EDR, backup, and orchestration agents that legitimately combine inbound acceptance with outbound fan-out."
    references = "reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_socket_fanout_or_forwarding.md"
    validation_status = "needs_validation"
    validation_method = "Test on synthetic relay fixtures and representative authorized proxy baselines that combine inbound and outbound legs."
    review_status = "reviewed"
    review_reference = "reviews/cobalt-strike-beacon/detection-review.md"
    compensates_for = "cobalt_strike_socket_fanout_or_forwarding"
    source_comparison = "public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_socket_fanout_or_forwarding.md"
    modification_note = "Proposal accepted with a required change: replaced the PID-based join with the stable principal/target.process.entity_id field, consistent with the existing cross_process_injection rule and detection-review finding DR-02, which already established that PID reuse can create false joins in this rule family."
  events:
    $in.metadata.event_type = "NETWORK_CONNECTION"
    $in.principal.hostname = $host
    $in.network.direction = "INBOUND"
    $in.target.process.product_specific_process_id = $proc
    $out.metadata.event_type = "NETWORK_CONNECTION"
    $out.principal.hostname = $host
    $out.network.direction = "OUTBOUND"
    $out.principal.process.product_specific_process_id = $proc
    $out.target.ip = $destination
    $in.metadata.event_timestamp.seconds <= $out.metadata.event_timestamp.seconds
  match:
    $host, $proc over 15m
  outcome:
    $destinations = count_distinct($destination)
  condition:
    $in and $out and $destinations >= 5
}
```

- Re-comparison outcome: the revised rule closes the branch the proposal targeted, within its declared telemetry. Remaining limits are the accepted gaps in `reviews/cobalt-strike-beacon/detection-review.md`, each with a named compensating rule.
