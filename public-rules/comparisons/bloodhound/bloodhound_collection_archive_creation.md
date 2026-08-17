# Public-rule comparison: bloodhound_collection_archive_creation

## Identity and independence gate

- Internal tool: `bloodhound`
- Internal canonical rule: `detections/bloodhound/yaral/bloodhound_collection_archive_creation.yaral`
- Internal SHA-256: `db96982a0d4ad110faecfee9dc90144cb713a7000308c6f2382142a3c1e528c1`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `BH-015`
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate:
- [Elastic PowerShell compression building block](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules_building_block/collection_posh_compression.toml) - pinned revision and SHA-256 `e1393ea2bfc404db1a32e2ca4b1deda3d907371d53f9477ac168d98942ddd5ed`.

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

- Candidate improvement: independently add the missing procedure branch shown below; no public predicate is copied.
- Independent verification: compare against pinned collector source, actual provider semantics, sanitized fixtures and benign inventory baselines.
- Decision: `deferred_pending_rule_improvement_run`.
- Reason: comparison code is an unvalidated detection-engineering proposal, not canonical logic.
- Required regeneration: canonical review, coverage, telemetry, all translations, dependencies/hashes and this comparison after acceptance or modification.

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
