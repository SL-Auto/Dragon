# Public-rule comparison: bloodhound_cloud_collection_output

## Identity and independence gate

- Internal tool: `bloodhound`
- Internal canonical rule: `detections/bloodhound/yaral/bloodhound_cloud_collection_output.yaral`
- Internal SHA-256: `d395281a6c6b71517d46e12d5ab71d8f5f5335ae1d9341350e126d1fd8713f13`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `BH-020`
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate:
- [Elastic AzureHound user-agent rule](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/integrations/azure/discovery_bloodhound_user_agents_detected.toml) - pinned revision and SHA-256 `ae4b54c0bd1908c0eefc9f7b8e315a543ee1e3e5795578329fea972e02ffac60`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| sustained cloud reads correlate with local JSON output or collector service lifecycle | twenty reads plus any JSON create or 4697/7045 by same host/user | AzureHound user-agent signal, without endpoint output correlation | same process entity performs cloud reads and creates collector output - strong | host/user correlation to generic JSON or service event - weak | public_stronger | Canonical rule, pinned public candidate, `coverage/bloodhound.yml` and `reports/bloodhound/source-analysis.md`. |
| Activity is divided across identities, hosts, processes or windows | Usually falls below the current cardinality/join | Public candidate also lacks complete distributed correlation | stable entity plus procedure-specific effect - moderate | longer-window baseline/rare relationship - moderate | insufficient_evidence | This is an analytical inference requiring tenant telemetry validation. |

## Missing detection branches

- Missing from ours: remote/cloud execution with no hostname, stdout/object-storage output, process entity join, service identity mismatch and non-JSON formats.
- Missing from public rule: complete ordered procedure coverage and telemetry-independent attribution beyond its declared data source.
- Missing from both: reliable intent attribution and complete observation when required logging is absent.

## Detection edge cases and blind spots

Host/user is too coarse and can join unrelated inventory activity to any service installation or JSON file. Low-and-slow and distributed activity can evade fixed per-entity windows. Partial collection can reduce cardinality without indicating benign behavior. Entity normalization must distinguish user, application, process and host identities.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| same process entity performs cloud reads and creates collector output | strong | ours/proposal | Close to the security-relevant collection effect and resistant to mutable filenames. | Requires the detailed telemetry declared below and authorized-tool baselining. |
| procedure-specific breadth or ordered correlation | moderate | ours | Adds behavioral context without asserting tool identity. | Thresholds and joins require local validation. |
| host/user correlation to generic JSON or service event | weak | public or current branch | Useful as a lead but not sufficient proof of collection. | Mutable or common in legitimate administration. |

## Public-rule weaknesses

The public candidate covers only its declared observable and does not establish the complete BloodHound collection procedure. Its implementation-specific or single-source signal can be absent while the same security effect remains observable elsewhere. It is valuable as independent compensating evidence, not authority.

## Internal-rule weaknesses

remote/cloud execution with no hostname, stdout/object-storage output, process entity join, service identity mismatch and non-JSON formats. The current threshold and entity join are detection hypotheses; collection loss can silently turn a strong sequence into no alert.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown below; no public predicate is copied.
- Independent verification: compare against pinned collector source, actual provider semantics, sanitized fixtures and benign inventory baselines.
- Decision: `deferred_pending_rule_improvement_run`.
- Reason: comparison code is an unvalidated detection-engineering proposal, not canonical logic.
- Required regeneration: canonical review, coverage, telemetry, all translations, dependencies/hashes and this comparison after acceptance or modification.

## Unmatched scope

The pinned public candidate is not a complete equivalent. Branch-specific differences are retained as `public_stronger` or `insufficient_evidence` rather than claiming either rule is globally better.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: remote/cloud execution with no hostname, stdout/object-storage output, process entity join, service identity mismatch and non-JSON formats.
- Required telemetry: process-attributed Graph/ARM egress or gateway-to-process correlation plus endpoint file creation.
- Validation status: `unvalidated_proposal`

```yaral
rule bloodhound_cloud_read_to_local_output {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "BH-020"
  events:
    $n.metadata.product_event_type = /(MicrosoftGraphActivityLogs|AZURE_RESOURCE_READ)/
    $n.principal.hostname = $host
    $n.principal.process.product_specific_process_id = $entity
    $n.target.resource.attribute.labels["resource_family"] = $family
    $f.metadata.product_event_type = /(11|FILE_CREATION)/
    $f.principal.hostname = $host
    $f.principal.process.product_specific_process_id = $entity
    re.regex($f.target.file.full_path, `(?i)\.(json|zip)$`)
  match:
    $host, $entity over 60m
  outcome:
    $families = count_distinct($family)
  condition:
    $families >= 5 and $f
}
```

Remaining gaps: intent is not established; thresholds, normalized fields and benign baselines require authorized telemetry testing. Distributed activity and missing collection require separate compensating analytics and collection-health monitoring.

If adopted, independently revise canonical YARA-L, re-run adversarial review, reconcile telemetry and master counts, regenerate all five translations and dependencies, and re-compare the final logic.
