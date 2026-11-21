# Public-rule comparison: bloodhound_collection_archive_creation

## Identity and independence gate

- Internal tool: `bloodhound`
- Internal canonical rule: `detections/bloodhound/yaral/bloodhound_collection_archive_creation.yaral`
- Internal SHA-256: `db96982a0d4ad110faecfee9dc90144cb713a7000308c6f2382142a3c1e528c1`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `BH-015`
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate:
- [Elastic PowerShell compression building block](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules_building_block/collection_posh_compression.toml) - pinned revision and SHA-256 `425d1333010d080e7846291b6546195b89b0bafeb2536d46336866d6feb2de6e`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| multiple JSON collection files are created then packaged into an archive | same PID creates three JSON files and ZIP/7z in ten minutes | PowerShell compression command/activity building block | same stable process entity creates several collector-schema files and an archive - strong | archive extension or compression command alone - weak | complementary | Canonical rule, pinned public candidate, `coverage/bloodhound.yml` and `reports/bloodhound/source-analysis.md`. |
| Activity is divided across identities, hosts, processes or windows | Usually falls below the current cardinality/join | Public candidate also lacks complete distributed correlation | stable entity plus procedure-specific effect - moderate | longer-window baseline/rare relationship - moderate | insufficient_evidence | This is an analytical inference requiring tenant telemetry validation. |

## Missing detection branches

- Missing from ours: CSV output, process restart, non-ZIP output, in-memory output, service output and deletion lifecycle.
- Missing from public rule: complete ordered procedure coverage and telemetry-independent attribution beyond its declared data source.
- Missing from both: reliable intent attribution and complete observation when required logging is absent.

## Detection edge cases and blind spots

PID reuse and missing process entity IDs can misjoin; JSON archiving is common; the public PowerShell branch is implementation-specific. Low-and-slow and distributed activity can evade fixed per-entity windows. Partial collection can reduce cardinality without indicating benign behavior. Entity normalization must distinguish user, application, process and host identities.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| same stable process entity creates several collector-schema files and an archive | strong | ours/proposal | Close to the security-relevant collection effect and resistant to mutable filenames. | Requires the detailed telemetry declared below and authorized-tool baselining. |
| procedure-specific breadth or ordered correlation | moderate | ours | Adds behavioral context without asserting tool identity. | Thresholds and joins require local validation. |
| archive extension or compression command alone | weak | public or current branch | Useful as a lead but not sufficient proof of collection. | Mutable or common in legitimate administration. |

## Public-rule weaknesses

The public candidate covers only its declared observable and does not establish the complete BloodHound collection procedure. Its implementation-specific or single-source signal can be absent while the same security effect remains observable elsewhere. It is valuable as independent compensating evidence, not authority.

## Internal-rule weaknesses

CSV output, process restart, non-ZIP output, in-memory output, service output and deletion lifecycle. The current threshold and entity join are detection hypotheses; collection loss can silently turn a strong sequence into no alert.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/bloodhound/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`, although the proposal had been copied, with divergences, into canonical YARA-L on 2026-08-16 without a recorded decision or review finding; the live rule was re-reviewed before this terminal decision.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - The adoption counts JSON/CSV creates (`#j >= 3`) instead of distinct MD5 values, which file-creation events often lack, over 10 minutes.
  - Re-review added a host join to both events, so identical PIDs on different hosts cannot correlate (BH-DR-28).
- Canonical result: `detections/bloodhound/yaral/bloodhound_collection_archive_creation.yaral`, SHA-256 `5b6f313c2e5dc7860ffa614e1f7fe38dbde4330f11a8affce79a099df57bb85a`.
- Regeneration: canonical change on 2026-11-21; detection review, `telemetry/bloodhound.md`, `telemetry/MASTER.md` counts, five translations, dependency/manifest hashes and this re-comparison were regenerated in the same run.

## Unmatched scope

The pinned public candidate is not a complete equivalent. Branch-specific differences are retained as `complementary` or `insufficient_evidence` rather than claiming either rule is globally better.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: CSV output, process restart, non-ZIP output, in-memory output, service output and deletion lifecycle.
- Required telemetry: stable process entity, file creates, extensions, and privacy-safe collector-schema fingerprint enrichment.
- Validation status: `unvalidated_proposal`

```yaral
rule bloodhound_collection_artifact_packaging {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "BH-015"
  events:
    $j.metadata.product_event_type = /(11|FILE_CREATION)/
    $j.principal.process.product_specific_process_id = $entity
    re.regex($j.target.file.full_path, `(?i)\.(json|csv)$`)
    $j.target.file.md5 = $schema
    $a.metadata.product_event_type = /(11|FILE_CREATION)/
    $a.principal.process.product_specific_process_id = $entity
    re.regex($a.target.file.full_path, `(?i)\.(zip|7z)$`)
  match:
    $entity over 20m
  outcome:
    $schemas = count_distinct($schema)
  condition:
    $schemas >= 3 and $a
}
```

Remaining gaps: intent is not established; thresholds, normalized fields and benign baselines require authorized telemetry testing. Distributed activity and missing collection require separate compensating analytics and collection-health monitoring.

If adopted, independently revise canonical YARA-L, re-run adversarial review, reconcile telemetry and master counts, regenerate all five translations and dependencies, and re-compare the final logic.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules_building_block/collection_posh_compression.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Same process writes multiple JSON/CSV files and an archive | covered (host plus process) | `collection_posh_compression.toml` (building block): PowerShell script blocks using compression cmdlets/classes | file creates plus archive - moderate | script-block compression - weak | complementary |
| Compiled collector archiving without PowerShell | covered | not covered | file events - moderate | none | ours_stronger |

- Current canonical YARA-L `detections/bloodhound/yaral/bloodhound_collection_archive_creation.yaral` (`experimental` / `needs_validation`):

```yaral
rule bloodhound_collection_archive_creation {
  meta:
    author = "Detection Research Agent"
    description = "Correlates multiple JSON or CSV file creations with archive creation by one process."
    date = "2026-11-21"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "The collection artifact lifecycle is useful but filenames and archive formats are mutable."
    procedure_ids = "BH-015"
    log_source_prerequisites = "EDR or Sysmon file create/delete events with stable process entity, path and extension."
    false_positives = "Backup, export, packaging, browser download and administrative reporting software."
    references = "reports/bloodhound/source-analysis.md, public-rules/comparisons/bloodhound/bloodhound_collection_archive_creation.md, reviews/bloodhound/detection-review.md#bh-dr-28"
    validation_status = "needs_validation"
    validation_method = "Use benign multi-JSON/CSV archive fixtures with reordered and missing-delete cases."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/bloodhound/detection-review.md"
  events:
    $j.metadata.product_event_type = /^(11|FILE_CREATION)$/
    $j.principal.hostname = $host
    $j.principal.process.product_specific_process_id = $process
    re.regex($j.target.file.full_path, `(?i)\.(json|csv)$`)
    $a.metadata.product_event_type = /^(11|FILE_CREATION)$/
    $a.principal.hostname = $host
    $a.principal.process.product_specific_process_id = $process
    re.regex($a.target.file.full_path, `(?i)\.(zip|7z)$`)
  match:
    $host, $process over 10m
  condition:
    #j >= 3 and $a
}
```

- Re-comparison outcome: the current canonical rule closes the branch the proposal targeted, within declared telemetry; remaining gaps are recorded in `reviews/bloodhound/detection-review.md`.
