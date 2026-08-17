# Public-rule comparison: bloodhound_service_protocol_probe_fanout

## Identity and independence gate

- Internal tool: `bloodhound`
- Internal canonical rule: `detections/bloodhound/yaral/bloodhound_service_protocol_probe_fanout.yaral`
- Internal SHA-256: `c43d112537c0702031905091e58e6b20039046261072b34a231ee12810f03bfe`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `BH-013`
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate:
- [Elastic potential port scan detection](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/network/discovery_potential_port_scan_detected.toml) - pinned revision and SHA-256 `ff6eb58e49ef06b1940b613b95b40faf2cb0388469c8776abec63edea717ca1b`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| one process probes WebDAV, SMB, LDAP and LDAPS capability across many hosts | 15 targets on any listed port, without protocol diversity | no equivalent multi-protocol collection branch | same process probes several relevant protocols across many internal targets - strong | target count on a union of common ports - weak | different_scope | Canonical rule, pinned public candidate, `coverage/bloodhound.yml` and `reports/bloodhound/source-analysis.md`. |
| Activity is divided across identities, hosts, processes or windows | Usually falls below the current cardinality/join | Public candidate also lacks complete distributed correlation | stable entity plus procedure-specific effect - moderate | longer-window baseline/rare relationship - moderate | insufficient_evidence | This is an analytical inference requiring tenant telemetry validation. |

## Missing detection branches

- Missing from ours: protocol-family diversity, connection results, HTTP WebDAV methods, low-and-slow probes and DNS.
- Missing from public rule: complete ordered procedure coverage and telemetry-independent attribution beyond its declared data source.
- Missing from both: reliable intent attribution and complete observation when required logging is absent.

## Detection edge cases and blind spots

The current rule can fire on ordinary web browsing or SMB-only scanners because it does not require multiple service families. Low-and-slow and distributed activity can evade fixed per-entity windows. Partial collection can reduce cardinality without indicating benign behavior. Entity normalization must distinguish user, application, process and host identities.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| same process probes several relevant protocols across many internal targets | strong | ours/proposal | Close to the security-relevant collection effect and resistant to mutable filenames. | Requires the detailed telemetry declared below and authorized-tool baselining. |
| procedure-specific breadth or ordered correlation | moderate | ours | Adds behavioral context without asserting tool identity. | Thresholds and joins require local validation. |
| target count on a union of common ports | weak | public or current branch | Useful as a lead but not sufficient proof of collection. | Mutable or common in legitimate administration. |

## Public-rule weaknesses

The public candidate covers only its declared observable and does not establish the complete BloodHound collection procedure. Its implementation-specific or single-source signal can be absent while the same security effect remains observable elsewhere. It is valuable as independent compensating evidence, not authority.

## Internal-rule weaknesses

protocol-family diversity, connection results, HTTP WebDAV methods, low-and-slow probes and DNS. The current threshold and entity join are detection hypotheses; collection loss can silently turn a strong sequence into no alert.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown below; no public predicate is copied.
- Independent verification: compare against pinned collector source, actual provider semantics, sanitized fixtures and benign inventory baselines.
- Decision: `deferred_pending_rule_improvement_run`.
- Reason: comparison code is an unvalidated detection-engineering proposal, not canonical logic.
- Required regeneration: canonical review, coverage, telemetry, all translations, dependencies/hashes and this comparison after acceptance or modification.

## Unmatched scope

The pinned public candidate is not a complete equivalent. Branch-specific differences are retained as `different_scope` or `insufficient_evidence` rather than claiming either rule is globally better.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: protocol-family diversity, connection results, HTTP WebDAV methods, low-and-slow probes and DNS.
- Required telemetry: process-attributed flows with reliable application/service classification and internal target identity.
- Validation status: `unvalidated_proposal`

```yaral
rule bloodhound_multi_protocol_capability_probe {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "BH-013"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.principal.hostname = $host
    $e.principal.process.product_specific_process_id = $pid
    $e.target.ip = $target
    $e.target.resource.attribute.labels["service_family"] = $service
    $service = /(?i)(webdav|smb|ldap|ldaps)/
  match:
    $host, $pid over 30m
  outcome:
    $targets = count_distinct($target)
    $services = count_distinct($service)
  condition:
    $e and $targets >= 10 and $services >= 3
}
```

Remaining gaps: intent is not established; thresholds, normalized fields and benign baselines require authorized telemetry testing. Distributed activity and missing collection require separate compensating analytics and collection-health monitoring.

If adopted, independently revise canonical YARA-L, re-run adversarial review, reconcile telemetry and master counts, regenerate all five translations and dependencies, and re-compare the final logic.
