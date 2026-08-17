# Public-rule comparison: bloodhound_smb_rpc_host_sweep

## Identity and independence gate

- Internal tool: `bloodhound`
- Internal canonical rule: `detections/bloodhound/yaral/bloodhound_smb_rpc_host_sweep.yaral`
- Internal SHA-256: `b8d1ae76299c59a46d6fc07d88377ec4c878d08703ea36be38123d18059ff65d`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `BH-006`
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate:
- [Elastic potential port scan detection](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/network/discovery_potential_port_scan_detected.toml) - pinned revision and SHA-256 `ff6eb58e49ef06b1940b613b95b40faf2cb0388469c8776abec63edea717ca1b`.

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

- Candidate improvement: independently add the missing procedure branch shown below; no public predicate is copied.
- Independent verification: compare against pinned collector source, actual provider semantics, sanitized fixtures and benign inventory baselines.
- Decision: `deferred_pending_rule_improvement_run`.
- Reason: comparison code is an unvalidated detection-engineering proposal, not canonical logic.
- Required regeneration: canonical review, coverage, telemetry, all translations, dependencies/hashes and this comparison after acceptance or modification.

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
