# Public-rule comparison: bloodhound_smb_rpc_host_sweep

## Identity and independence gate

- Internal tool: `bloodhound`
- Internal canonical rule: `detections/bloodhound/yaral/bloodhound_smb_rpc_host_sweep.yaral`
- Internal SHA-256: `b8d1ae76299c59a46d6fc07d88377ec4c878d08703ea36be38123d18059ff65d`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `BH-006`
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate:
- [Elastic potential port scan detection](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/network/discovery_potential_port_scan_detected.toml) - pinned revision and SHA-256 `ca8b527f02d8ffb8c81e05acfe1b84f953002d5a676a052030b97203679e9341`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| one process resolves and probes many hosts over SMB/RPC | 20 distinct 135/139/445 destinations in ten minutes | no material host-sweep equivalent; closest rule observes downstream AD property access | process-attributed east-west multi-host connection fanout with failure/success context - strong | port fanout without internal-scope or process trust context - weak | ours_stronger | Canonical rule, pinned public candidate, `coverage/bloodhound.yml` and `reports/bloodhound/source-analysis.md`. |
| Activity is divided across identities, hosts, processes or windows | Usually falls below the current cardinality/join | Public candidate also lacks complete distributed correlation | stable entity plus procedure-specific effect - moderate | longer-window baseline/rare relationship - moderate | insufficient_evidence | This is an analytical inference requiring tenant telemetry validation. |

## Missing detection branches

- Missing from ours: DNS-only discovery, failed probes missing from flow, IPv6, slow/distributed sweeps, and target-host rather than IP counting.
- Missing from public rule: complete ordered procedure coverage and telemetry-independent attribution beyond its declared data source.
- Missing from both: reliable intent attribution and complete observation when required logging is absent.

## Detection edge cases and blind spots

Shared scanners and management systems dominate false positives; IP churn can inflate cardinality while NAT can merge actors. Low-and-slow and distributed activity can evade fixed per-entity windows. Partial collection can reduce cardinality without indicating benign behavior. Entity normalization must distinguish user, application, process and host identities.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| process-attributed east-west multi-host connection fanout with failure/success context | strong | ours/proposal | Close to the security-relevant collection effect and resistant to mutable filenames. | Requires the detailed telemetry declared below and authorized-tool baselining. |
| procedure-specific breadth or ordered correlation | moderate | ours | Adds behavioral context without asserting tool identity. | Thresholds and joins require local validation. |
| port fanout without internal-scope or process trust context | weak | public or current branch | Useful as a lead but not sufficient proof of collection. | Mutable or common in legitimate administration. |

## Public-rule weaknesses

The public candidate covers only its declared observable and does not establish the complete BloodHound collection procedure. Its implementation-specific or single-source signal can be absent while the same security effect remains observable elsewhere. It is valuable as independent compensating evidence, not authority.

## Internal-rule weaknesses

DNS-only discovery, failed probes missing from flow, IPv6, slow/distributed sweeps, and target-host rather than IP counting. The current threshold and entity join are detection hypotheses; collection loss can silently turn a strong sequence into no alert.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/bloodhound/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`, although the proposal had been copied, with divergences, into canonical YARA-L on 2026-08-16 without a recorded decision or review finding; the live rule was re-reviewed before this terminal decision.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - The adoption fails open on the scanner approval (`!= "true"`) rather than the proposal's fail-closed `= "false"`, and keys on the process image.
  - Re-review replaced the invalid regex comparison on integer `target.port` with equality alternations, and restored the proposal's 30-minute window for throttled sweeps (BH-DR-30).
- Canonical result: `detections/bloodhound/yaral/bloodhound_smb_rpc_host_sweep.yaral`, SHA-256 `17d41ccc89b20de8cc7378288effe9cd41ee26049fa371513df1cb9a4591793f`.
- Regeneration: canonical change on 2026-11-21; detection review, `telemetry/bloodhound.md`, `telemetry/MASTER.md` counts, five translations, dependency/manifest hashes and this re-comparison were regenerated in the same run.

## Unmatched scope

The pinned public candidate is not a complete equivalent. Branch-specific differences are retained as `ours_stronger` or `insufficient_evidence` rather than claiming either rule is globally better.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: DNS-only discovery, failed probes missing from flow, IPv6, slow/distributed sweeps, and target-host rather than IP counting.
- Required telemetry: process-attributed attempted connections, internal-address enrichment, stable process entity and governed scanner inventory.
- Validation status: `unvalidated_proposal`

```yaral
rule bloodhound_smb_rpc_host_sweep_internal_untrusted {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "BH-006"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.principal.hostname = $host
    $e.principal.process.product_specific_process_id = $pid
    $e.target.ip = $target
    $e.target.port = /(135|139|445)/
    $e.target.ip_in_internal_range = true
    $e.principal.process.file.labels["approved_scanner"] = "false"
  match:
    $host, $pid over 30m
  outcome:
    $targets = count_distinct($target)
  condition:
    $e and $targets >= 15
}
```

Remaining gaps: intent is not established; thresholds, normalized fields and benign baselines require authorized telemetry testing. Distributed activity and missing collection require separate compensating analytics and collection-health monitoring.

If adopted, independently revise canonical YARA-L, re-run adversarial review, reconcile telemetry and master counts, regenerate all five translations and dependencies, and re-compare the final logic.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/network/discovery_potential_port_scan_detected.toml` changed between 7e91c15 and 9d792a8; re-read on 2026-11-21: the ES|QL now restricts input to connection-type flow events from named datasets, while still counting distinct destination ports per source/destination pair. It remains a vertical-scan rule, so the `different_scope` conclusion stands.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| One process connecting to 135/139/445 on many internal hosts | covered (>= 15 targets over 30 minutes) | `discovery_potential_port_scan_detected.toml`: ES|QL flow analytics counting distinct destination ports per source/destination pair (vertical scan); between `7e91c15` and `9d792a8` it narrowed which flow events count, without changing that scope | horizontal SMB/RPC breadth - moderate | probe fan-out rule - moderate | different_scope |
| Many ports on one host | not targeted | covered | vertical port count - moderate | none | different_scope |

- Current canonical YARA-L `detections/bloodhound/yaral/bloodhound_smb_rpc_host_sweep.yaral` (`experimental` / `needs_validation`):

```yaral
rule bloodhound_smb_rpc_host_sweep {
  meta:
    author = "Detection Research Agent"
    description = "Detects one process attempting SMB or RPC connections to many internal hosts, excluding destinations outside the internal address range and sources labeled as an approved scanner."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Process-attributed east-west fanout is a strong active host-discovery signal."
    procedure_ids = "BH-006"
    log_source_prerequisites = "EDR/firewall network events with source process, destination host/IP and port, internal-address-range enrichment and governed scanner-inventory labeling."
    false_positives = "Vulnerability scanners, deployment systems, backup discovery and approved inventory not present in the scanner-inventory label; a stale or incomplete inventory can still allow false positives."
    references = "reports/bloodhound/source-analysis.md, public-rules/comparisons/bloodhound/bloodhound_smb_rpc_host_sweep.md, reviews/bloodhound/detection-review.md#bh-dr-30"
    validation_status = "needs_validation"
    validation_method = "Baseline approved scanners and test distinct-target boundaries with synthetic internal and external flows, including missing/stale scanner-inventory labels."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/bloodhound/detection-review.md"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.principal.hostname = $host
    $e.principal.process.file.full_path = $process
    $e.target.ip = $target
    ($e.target.port = 135 or $e.target.port = 139 or $e.target.port = 445)
    $e.target.ip_in_internal_range = true
    $e.principal.process.file.labels["approved_scanner"] != "true"
  match:
    $host, $process over 30m
  outcome:
    $targets = count_distinct($target)
  condition:
    $e and $targets >= 15
}
```

- Re-comparison outcome: the current canonical rule closes the branch the proposal targeted, within declared telemetry; remaining gaps are recorded in `reviews/bloodhound/detection-review.md`.
