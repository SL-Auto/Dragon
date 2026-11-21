# Public-rule comparison: cobalt_strike_discovery_fanout

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_discovery_fanout.yaral`
- Internal SHA-256: `7868c485d52f83087d38e03a214bd53cd71c5dea728ff92e8d0f485418d51882`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-021`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/recon_environment_enumeration_network_cisa_report.yaral`](../../snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/recon_environment_enumeration_network_cisa_report.yaral) - SHA-256 `0f078d23411336ac984a8467863b0ed8ad8a8b040de657941d5014f6ae158587`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite and execution context | Process/entity context is retained | Candidate supplies a narrower implementation-specific context | Process attribution - moderate | identity/session baseline | complementary | Canonical rule and pinned candidate above. |
| network and port discovery across many destinations | destination fan-out from one process | recon rules add suspicious command and environment-enumeration branches but rely more on mutable command lines | rare process network fan-out - moderate | ordered downstream security effect | complementary | Procedure `CSB-021` and the cited public rule cover overlapping but non-identical observables. |
| Resulting security effect or artifact | Partially covered | Partially covered | result correlation - strong when present | host/user/time-bounded sequence | different_scope | Neither rule proves every procedure outcome. |

## Missing detection branches

- Missing from ours: slow or distributed scans and sequential port probing below the distinct-host threshold.
- Missing from the public candidate: the complete tool-independent ordered procedure and all Beacon-supported implementation variants.
- Missing from both: reliable attribution to Cobalt Strike; these are behavioral detections and must not claim tool identity.

## Detection edge cases and blind spots

vulnerability scanners and management agents have identical fan-out. Partial collection, clock skew, event loss, and process or identity key reuse can also break correlations. Low-and-slow activity may fall outside fixed windows, while distributing steps across processes can defeat same-process joins. These are detection limitations, not operational guidance.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| rare process network fan-out | moderate | ours | Close to the relevant security effect and less dependent on mutable names. | Depends on normalized process/entity fields and local baselines. |
| Candidate implementation indicator | moderate | public | Adds a concrete observable branch absent from ours. | Often tied to one implementation, field model, or default. |
| Name, path, or command fragment alone | weak | public where present | Useful only as context, not proof of the procedure. | Mutable and commonly overlaps administration. |

## Public-rule weaknesses

The candidate is useful as an independent compensating branch, but its narrower implementation assumptions do not cover the complete procedure. Any literal names, paths, command fragments, fixed thresholds, or product enrichments remain fragile until validated locally. It must not be copied blindly.

## Internal-rule weaknesses

The canonical rule has broader tool-independent intent, but slow or distributed scans and sequential port probing below the distinct-host threshold. Its correlation also assumes consistent entity normalization and adequate collection across the declared window.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against source analysis, provider field semantics and `reviews/cobalt-strike-beacon/detection-review.md`.
- Prior state: the proposal was copied into canonical YARA-L on 2026-08-16 while this trail read `deferred_pending_rule_improvement_run`, a non-terminal state the workflow prohibits. It is re-decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real, but adversarial review found defects in the proposal as written; the adopted rule diverges as follows:
  - Approval enrichment now fails open with `!= true`, so missing enrichment cannot silently suppress (DR-16).
  - Distinct IP/port counts moved to `outcome`.
- Canonical result: `detections/cobalt-strike-beacon/yaral/cobalt_strike_discovery_fanout_compensating_signal.yaral`, SHA-256 `21802ffed35a72cabcb273832f37a7663a5d0079a9ced3fc26d18754697a8295`. The original proposal is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration completed in the same run: detection review, coverage ledger, tool telemetry file, `telemetry/MASTER.md` counts, all five translations, translation review, dependency/manifest hashes, and the re-comparison below.
## Unmatched scope

The public candidate does not cover all branches in `CSB-021`. Conversely, the canonical rule is not evidence of Cobalt Strike attribution and may detect other tooling with equivalent effects.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: slow or distributed scans and sequential port probing below the distinct-host threshold.
- Required telemetry: normalized `NETWORK_CONNECTION` plus the entity, enrichment, and correlation fields used below; collection health must be monitored.
- Validation status: `unvalidated_proposal`

```yaral
rule cobalt_strike_discovery_fanout_compensating_signal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    description = "Independent compensating signal proposed after public-rule comparison"
    procedure_ids = "CSB-021"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
        $e.principal.user.userid = $user
        $e.principal.hostname = $host
        $e.target.ip = $ip
        $e.target.port = $port
        $e.additional.fields["approved_scanner"].value.bool_value = false
  match:
    $user, $host over 60m
  condition:
    $e and #ip >= 10 and #port >= 4
}
```

This proposal is deliberately not canonical. Thresholds, field availability, benign prevalence, and join stability require adversarial review. Remaining gaps include telemetry loss, cross-host clock skew, and variants that do not produce the proposed effect.

If accepted or modified, update the canonical rule in the same run and regenerate every required downstream artifact before marking the comparison complete.

## Re-comparison against revised canonical rule

- Revised rule SHA-256 `21802ffed35a72cabcb273832f37a7663a5d0079a9ced3fc26d18754697a8295`, compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/community/microsoft/windows/recon_environment_enumeration_network_cisa_report.yaral` differs from the prior revision only in tag metadata or line endings; its detection logic is unchanged.

| Procedure branch / observable effect | Revised ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Slow or distributed port/network discovery | covered per user/host over 60m | `recon_environment_enumeration_network_cisa_report.yaral`: narrower implementation-specific context (original matrix); candidate not re-assessed beyond re-pinning | user/host IP and port breadth - moderate | base fan-out rule - moderate | complementary | Revised canonical rule, re-pinned candidate, `reviews/cobalt-strike-beacon/detection-review.md`. |

- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule cobalt_strike_discovery_fanout_compensating_signal {
  meta:
    author = "Detection Research Agent"
    description = "Aggregates attempted network connections by user and host over a wider window at a lower per-process threshold to surface slow or distributed port/network discovery that falls under the single-process fan-out rule's threshold."
    date = "2026-11-21"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "Session-scoped low-and-slow discovery is useful reconnaissance context, but vulnerability scanners and management agents produce identical fan-out."
    procedure_ids = "CSB-021"
    log_source_prerequisites = "Normalize process-attributed NETWORK_CONNECTION attempts with destination IP/port, account, hostname, and an allowlist enrichment identifying approved scanners."
    false_positives = "Vulnerability scanners, monitoring, software distribution, service discovery and network management tools not present in the approved-scanner enrichment."
    references = "reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_discovery_fanout.md"
    validation_status = "needs_validation"
    validation_method = "Replay authorized scanner baselines spread across many hosts and processes; confirm the allowlist enrichment suppresses them."
    review_status = "reviewed"
    review_reference = "reviews/cobalt-strike-beacon/detection-review.md"
    compensates_for = "cobalt_strike_discovery_fanout"
    source_comparison = "public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_discovery_fanout.md"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.principal.user.userid = $user
    $e.principal.hostname = $host
    $e.target.ip = $ip
    $e.target.port = $port
    $e.additional.fields["approved_scanner"].value.bool_value != true
  match:
    $user, $host over 60m
  outcome:
    $ips = count_distinct($ip)
    $ports = count_distinct($port)
  condition:
    $e and $ips >= 10 and $ports >= 4
}
```

- Re-comparison outcome: the revised rule closes the branch the proposal targeted, within its declared telemetry. Remaining limits are the accepted gaps in `reviews/cobalt-strike-beacon/detection-review.md`, each with a named compensating rule.
