# Public-rule comparison: sliver_process_access_from_network_process

## Identity and independence gate

- Internal tool: `sliver`
- Internal canonical rule: `detections/sliver/yaral/sliver_process_access_from_network_process.yaral`
- Internal SHA-256: `c05041c234b395b7a9ea6bbf7775a876ae726e1cac8821c7c1a1bf6f79109aaa`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-011,PROC-012,PROC-015`
- Scope mapping rationale: procedure, ordered behavior, security effect, platform and telemetry; names and syntax were not mapping criteria.

Public candidate:
- [`public-rules/snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/hacktool_generic_process_access.yaral`](../../snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/hacktool_generic_process_access.yaral) - SHA-256 `3e19f1fdcb5632b78d62e491cca65a8550d9e17b117bedfbc2fdc93cbaaf73aa`

## Procedure and detection-branch matrix

| Procedure branch / effect | Ours | Public | Primary signal and strength | Compensating signal | Conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Process/session prerequisite | Partial process or identity context | Adjacent behavior only | Stable process/session entity - moderate | signer, first-seen and host-role context | complementary | Internal `PROC-011,PROC-012,PROC-015` inventory; cited candidate. |
| egressing process performs sensitive process access, injection, memory load, or dump | Principal event family covered | Overlapping behavior under candidate-specific assumptions | network-active process obtains dangerous rights to a protected process - strong | ordered child/file/network/state effect - moderate | complementary | Security effect is closer to procedure than a tool name. |
| Result, recurrence or cleanup | Partial or absent | Partial or outside scope | Verified resulting state - strong | subsequent access, transfer, deletion or authentication - moderate | different_scope | Neither rule closes every downstream branch. |

## Missing detection branches

- Missing from ours: Distinct access, injection, assembly, library and dump signals are conflated; access mask and target sensitivity are not required.
- Missing from public: The public candidate does not cover complete Sliver procedure ordering, the internal process-to-effect correlation, or tool-name-independent downstream confirmation.
- Missing from both: activity split across processes/hosts, low-and-slow execution, encrypted application content, telemetry outages, and reliable confirmation of operator intent.

## Detection edge cases and blind spots

Process identifiers can be reused and differ across sensors; prefer a sensor-issued process entity ID when available. NAT, proxies, resolver infrastructure, delayed ingestion, clock skew and partial endpoint visibility can break ordering. Legitimate software deployment, remote support, browsers, proxies, backup, monitoring and administration overlap with individual primitives. Baselines should raise or lower confidence without excluding the sensitive effect. Distributed and low-rate activity needs longer-lived entity analytics rather than simply expanding every correlation window.

## Signal-quality assessment

| Signal | Strength | Used by | Reason | Fragility |
| --- | --- | --- | --- | --- |
| network-active process obtains dangerous rights to a protected process | strong | proposed refinement | Close to the security effect and behavior-based. | Requires stable entity joins and declared telemetry. |
| Process-attributed egress | moderate | ours | Valuable causal context but common alone. | Proxying and sensor gaps reduce attribution. |
| Image, argument, port or default name | weak | some public logic | Useful enrichment, not durable intent. | Mutable and common in benign workloads. |

## Public-rule weaknesses

The candidate supplies useful behaviorally relevant telemetry but not the whole Sliver procedure. Backend assumptions and fixed thresholds are not tenant validation; its predicates must not be copied blindly.

## Internal-rule weaknesses

Distinct access, injection, assembly, library and dump signals are conflated; access mask and target sensitivity are not required. Broad joins risk benign collisions; narrow windows and same-process assumptions risk false negatives during delayed, delegated or distributed behavior.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/sliver/detection-review.md`.
- Prior state: this trail still read `deferred_pending_rule_improvement_run`, although the 2026-08-16 backlog resolution (REVIEW-010 to REVIEW-014) had already acted on the proposal; this pass re-reviews that action and records the terminal decision.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - The narrow rule requires a Sysmon 10 handle to lsass, winlogon or csrss with a memory-read-capable access mask from an egressing PID.
  - Removed the proposal's `event_timestamp.seconds <=` ordering; bounded co-occurrence in the match window is kept (REVIEW-010).
  - Adopted as an additional narrow rule beside the broad base rule, not as a replacement, so procedures without the narrow sub-case keep coverage (REVIEW-012).
  - Anchored the access-mask alternation on 2026-11-21 (REVIEW-016).
- Canonical result: `detections/sliver/yaral/sliver_process_access_from_network_process.yaral`, SHA-256 `ff8160d9687d0e63c777243d44d89cda93c2d97e9155a5f50f13187bde584e92`.
- Canonical result: `detections/sliver/yaral/sliver_lsass_access_from_network_process.yaral`, SHA-256 `091ecdcf0fd295f8330119b536111b7e2e89eb4db59527449344dca067414710`.
- Regeneration: canonical change on 2026-11-21; detection review, telemetry row, five translations (after the generator anchoring fix), dependency/manifest hashes and this re-comparison were regenerated in the same run.

## Unmatched scope

The candidate does not cover all of `PROC-011,PROC-012,PROC-015`. No global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `split`
- Addresses branches: Distinct access, injection, assembly, library and dump signals are conflated; access mask and target sensitivity are not required.
- Required telemetry: stable process/session entity, actor, host, event time, action/result and procedure-specific file/network/state fields.
- Validation status: `unvalidated_proposal`

```yaral
rule sliver_process_access_from_network_process_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-011,PROC-012,PROC-015"
    source_comparison = "unvalidated_proposal"
  events:
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.process.pid = $pid
    $n.network.direction = "OUTBOUND"
    $a.metadata.product_event_type = "10"
    $a.principal.process.pid = $pid
    $a.target.process.file.full_path = /(?i)\\(lsass|winlogon|csrss)\.exe$/
    $a.target.process.access_mask = /(?i)(0x1fffff|0x1f0fff|0x143a|0x1010)/
  match:
    $pid over 10m
  condition:
    $n and $a
}
```

The proposal uses concrete telemetry semantics but does not prove tool identity. It remains limited by collection health, process-entity fidelity, enrichment quality and activity outside the window. If accepted or modified, complete the full downstream workflow; if rejected, preserve the rationale without changing canonical logic.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/community/microsoft/windows/hacktool_generic_process_access.yaral` differs between 234e922 and dbc9beb only in line endings (snapshot path moved where applicable); content is identical.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Egressing process opens a protected credential process for memory read | covered by `sliver_lsass_access_from_network_process` | `hacktool_generic_process_access.yaral`: process access by default hacktool image names | target identity plus access mask plus same-PID egress - strong | base rule - weak | complementary |
| Injection, assembly or library load into other processes | covered by base rule | not covered | module-load/process-access family - weak | none | ours_stronger |
| Renamed tool image performing process access | covered (behavioral, name-independent) | not covered (image-name dependent) | same-PID access plus egress - strong | none | ours_stronger |

- Current canonical YARA-L `detections/sliver/yaral/sliver_process_access_from_network_process.yaral` (`experimental` / `needs_validation`):

```yaral
rule sliver_process_access_from_network_process {
  meta:
    author = "Detection Research Agent"
    description = "Outbound-network process performs sensitive process access, injection, dump, or memory load"
    date = "2026-08-15"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Covers code execution migration and dumping"
    procedure_ids = "PROC-011,PROC-012,PROC-015"
    log_source_prerequisites = "Tenant-verified EDR process access/injection/memory event plus stable PID network telemetry"
    false_positives = "EDR, debuggers, profilers, accessibility"
    references = "reports/sliver/source-analysis.md"
    validation_status = "needs_validation"
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/sliver/detection-review.md"
  events:
    $a.metadata.event_type = "PROCESS_MODULE_LOAD"
    $a.principal.hostname = $host
    $a.principal.process.product_specific_process_id = $pid

    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.network.direction = "OUTBOUND"
    $n.principal.hostname = $host
    $n.principal.process.product_specific_process_id = $pid
  match: $host, $pid over 10m
  condition: $a and $n
}
```

- Current canonical YARA-L `detections/sliver/yaral/sliver_lsass_access_from_network_process.yaral` (`experimental` / `needs_validation`):

```yaral
rule sliver_lsass_access_from_network_process {
  meta:
    author = "Detection Research Agent"
    description = "A network-active process obtains a memory-read-capable handle to a protected credential process such as lsass"
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Target-process identity (lsass/winlogon/csrss) plus a memory-read access mask is a high-specificity credential-access signal, compensating for the broad process-access rule that conflates access, injection, assembly-load, library-load, and dump signals under one generic module-load predicate"
    procedure_ids = "PROC-011,PROC-012,PROC-015"
    log_source_prerequisites = "Tenant-verified EDR process-access event (for example Sysmon Event ID 10) with target process identity and access mask, plus process-attributed network telemetry sharing a stable process entity"
    false_positives = "EDR/AV agents, debuggers, and credential-backup tools that legitimately open lsass with read access"
    references = "reports/sliver/source-analysis.md, public-rules/comparisons/sliver/sliver_process_access_from_network_process.md, reviews/sliver/detection-review.md#review-016"
    validation_status = "needs_validation"
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/sliver/detection-review.md"
    source_comparison = "accepted_as_compensating_rule_from_unvalidated_proposal"
  events:
    $a.metadata.product_event_type = "10"
    $a.principal.hostname = $host
    $a.principal.process.product_specific_process_id = $pid
    re.regex($a.target.process.file.full_path, `(?i)\\(lsass|winlogon|csrss)\.exe$`)
    re.regex($a.target.process.access_mask, `(?i)^(0x1fffff|0x1f0fff|0x143a|0x1010)$`)

    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.network.direction = "OUTBOUND"
    $n.principal.hostname = $host
    $n.principal.process.product_specific_process_id = $pid
  match: $host, $pid over 10m
  condition: $a and $n
}
```

- Re-comparison outcome: the current canonical rule set closes the branch the proposal targeted, within declared telemetry. Remaining limits are the accepted gaps in `reviews/sliver/detection-review.md`.
