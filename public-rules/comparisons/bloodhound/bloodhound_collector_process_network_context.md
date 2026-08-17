# Public-rule comparison: bloodhound_collector_process_network_context

## Identity and independence gate

- Internal tool: `bloodhound`
- Internal canonical rule: `detections/bloodhound/yaral/bloodhound_collector_process_network_context.yaral`
- Internal SHA-256: `41b68e8a22f6baba8eb54e87f010ef0a83a130c44ab9267f6ac1bc5e7b962dd5`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `BH-001`
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate:
- [Elastic BloodHound user-agent detection](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/integrations/azure/discovery_bloodhound_user_agents_detected.toml) - pinned revision and SHA-256 `ae4b54c0bd1908c0eefc9f7b8e315a543ee1e3e5795578329fea972e02ffac60`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| collector process starts and establishes directory or cloud-management connections | rare process plus five process-attributed LDAP/Graph/ARM connections | high-volume AD property access, without process/network sequence | process-attributed sensitive-service connection followed by confirmed enumeration - strong | rare executable path alone - weak | complementary | Canonical rule, pinned public candidate, `coverage/bloodhound.yml` and `reports/bloodhound/source-analysis.md`. |
| Activity is divided across identities, hosts, processes or windows | Usually falls below the current cardinality/join | Public candidate also lacks complete distributed correlation | stable entity plus procedure-specific effect - moderate | longer-window baseline/rare relationship - moderate | insufficient_evidence | This is an analytical inference requiring tenant telemetry validation. |

## Missing detection branches

- Missing from ours: signed-but-new collectors; common host processes loading collector code; single-protocol or slow activity.
- Missing from public rule: complete ordered procedure coverage and telemetry-independent attribution beyond its declared data source.
- Missing from both: reliable intent attribution and complete observation when required logging is absent.

## Detection edge cases and blind spots

Process paths are mutable, prevalence can lag, NAT can blur cloud sources, and process/network joins may break across sensors. Low-and-slow and distributed activity can evade fixed per-entity windows. Partial collection can reduce cardinality without indicating benign behavior. Entity normalization must distinguish user, application, process and host identities.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| process-attributed sensitive-service connection followed by confirmed enumeration | strong | ours/proposal | Close to the security-relevant collection effect and resistant to mutable filenames. | Requires the detailed telemetry declared below and authorized-tool baselining. |
| procedure-specific breadth or ordered correlation | moderate | ours | Adds behavioral context without asserting tool identity. | Thresholds and joins require local validation. |
| rare executable path alone | weak | public or current branch | Useful as a lead but not sufficient proof of collection. | Mutable or common in legitimate administration. |

## Public-rule weaknesses

The public candidate covers only its declared observable and does not establish the complete BloodHound collection procedure. Its implementation-specific or single-source signal can be absent while the same security effect remains observable elsewhere. It is valuable as independent compensating evidence, not authority.

## Internal-rule weaknesses

signed-but-new collectors; common host processes loading collector code; single-protocol or slow activity. The current threshold and entity join are detection hypotheses; collection loss can silently turn a strong sequence into no alert.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown below; no public predicate is copied.
- Independent verification: compare against pinned collector source, actual provider semantics, sanitized fixtures and benign inventory baselines.
- Decision: `deferred_pending_rule_improvement_run`.
- Reason: comparison code is an unvalidated detection-engineering proposal, not canonical logic.
- Required regeneration: canonical review, coverage, telemetry, all translations, dependencies/hashes and this comparison after acceptance or modification.

## Unmatched scope

The pinned public candidate is not a complete equivalent. Branch-specific differences are retained as `complementary` or `insufficient_evidence` rather than claiming either rule is globally better.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: signed-but-new collectors; common host processes loading collector code; single-protocol or slow activity.
- Required telemetry: stable process entity on process launch and LDAP/Graph/ARM read events.
- Validation status: `unvalidated_proposal`

```yaral
rule bloodhound_process_to_directory_effect {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "BH-001"
  events:
    $p.metadata.event_type = "PROCESS_LAUNCH"
    $p.principal.hostname = $host
    $p.target.process.product_specific_process_id = $pid
    $q.metadata.product_event_type = /(LDAP_SEARCH|MicrosoftGraphActivityLogs|AZURE_RESOURCE_READ)/
    $q.principal.hostname = $host
    $q.principal.process.product_specific_process_id = $pid
    $q.target.resource.name = $object
  match:
    $host, $pid over 20m
  outcome:
    $objects = count_distinct($object)
  condition:
    $p and $objects >= 25
}
```

Remaining gaps: intent is not established; thresholds, normalized fields and benign baselines require authorized telemetry testing. Distributed activity and missing collection require separate compensating analytics and collection-health monitoring.

If adopted, independently revise canonical YARA-L, re-run adversarial review, reconcile telemetry and master counts, regenerate all five translations and dependencies, and re-compare the final logic.
