# Public-rule comparison: bloodhound_cloud_collection_output

## Identity and independence gate

- Internal tool: `bloodhound`
- Internal canonical rule: `detections/bloodhound/yaral/bloodhound_cloud_collection_output.yaral`
- Internal SHA-256: `d395281a6c6b71517d46e12d5ab71d8f5f5335ae1d9341350e126d1fd8713f13`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `BH-020`
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate:
- [Elastic AzureHound user-agent rule](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/azure/discovery_bloodhound_user_agents_detected.toml) - pinned revision and SHA-256 `23a2c98500bd2c50247d9d802f3681598a9844e77779b0c82682d5a85773826c`.

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

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/bloodhound/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`, although the proposal had been copied, with divergences, into canonical YARA-L on 2026-08-16 without a recorded decision or review finding; the live rule was re-reviewed before this terminal decision.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - The adoption joins cloud reads to local output by host and user rather than endpoint process ID, because cloud audit carries no endpoint PID (BH-DR-17).
  - It adds service-install output (4697/7045) for remote execution and limits files to JSON. Event-ID alternations were anchored earlier on 2026-11-21 (BH-DR-26).
- Canonical result: `detections/bloodhound/yaral/bloodhound_cloud_collection_output.yaral`, SHA-256 `64bde079b841adcc1d8c87dddc76adc76f490c35e094b8dee7f97c18ad17790b`.
- Regeneration: the 2026-08-16 adoption's translations, telemetry and hashes were re-verified current on 2026-11-21; no canonical change in this run.

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

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/integrations/azure/discovery_bloodhound_user_agents_detected.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Cloud reads followed by local JSON output on the same host and user | covered | `discovery_bloodhound_user_agents_detected.toml`: AzureHound/SharpHound/BloodHound user-agent strings in Microsoft cloud logs | resource-family breadth plus output file - moderate | archive rule - moderate | complementary |
| Collector identified by its default user agent | not targeted (mutable name) | covered | user-agent string - weak (mutable) | behavioral rules - moderate | different_scope |

- Current canonical YARA-L `detections/bloodhound/yaral/bloodhound_cloud_collection_output.yaral` (`experimental` / `needs_validation`):

```yaral
rule bloodhound_cloud_collection_output {
  meta:
    author = "Detection Research Agent"
    description = "Correlates sustained, resource-family-diverse Graph or ARM reads with local JSON output or service lifecycle effects on the same host/user."
    date = "2026-08-16"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "Collection output strengthens cloud enumeration context but overlaps legitimate exporters and services."
    procedure_ids = "BH-020"
    log_source_prerequisites = "Process-attributed cloud egress with resource-family enrichment, plus file creation or Windows service events joined by host/user."
    false_positives = "Cloud inventory exporters, scheduled governance jobs and authorized AzureHound deployments."
    references = "reports/bloodhound/source-analysis.md, public-rules/comparisons/bloodhound/bloodhound_cloud_collection_output.md"
    validation_status = "needs_validation"
    validation_method = "Use sanitized cloud-read and JSON/service effect fixtures without running collector software."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/bloodhound/detection-review.md"
  events:
    $n.metadata.product_event_type = /^(MicrosoftGraphActivityLogs|AzureActivity|AZURE_RESOURCE_READ)$/
    $n.principal.hostname = $host
    $n.principal.user.userid = $user
    $n.target.resource.attribute.labels["resource_family"] = $family
    $f.metadata.product_event_type = /^(11|FILE_CREATION|4697|7045)$/
    $f.principal.hostname = $host
    $f.principal.user.userid = $user
    (re.regex($f.target.file.full_path, `(?i)\.json$`) or $f.metadata.product_event_type = /^(4697|7045)$/)
  match:
    $host, $user over 30m
  outcome:
    $families = count_distinct($family)
  condition:
    $families >= 5 and $f
}
```

- Re-comparison outcome: the current canonical rule closes the branch the proposal targeted, within declared telemetry; remaining gaps are recorded in `reviews/bloodhound/detection-review.md`.
