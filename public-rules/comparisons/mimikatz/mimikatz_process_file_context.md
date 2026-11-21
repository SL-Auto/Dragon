# Public-rule comparison: mimikatz_process_file_context

## Identity and independence gate

- Internal tool: `mimikatz`
- Internal canonical rule: `detections/mimikatz/yaral/mimikatz_process_file_context.yaral`
- Internal SHA-256: `c5016a0deda0568294c2efa730dd0fec183eaa5f0bc2ac3e100b4cc7c3cf4928`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `P01,P31,P33`
- Scope mapping rationale: mapped by security effect, ordered procedure and required telemetry; names and syntax were not mapping criteria.

Public evidence:
- Behaviorally relevant public candidate: [protected hive movement](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/credential_access_moving_registry_hive_via_smb.toml) - pinned Elastic revision `7e91c156324cdc64cda27f7fec7067b1148074ef`; SHA-256 `230a77a5247b40022dcfee97a113d637644eef645137078311766a7ce252deea`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| utility execution, spawned tools and transformed/staged output create process/file context | process plus file lifecycle correlation | protected hive movement only | untrusted process creates multiple sensitive credential/ticket/hive artifact classes - strong | filename or command keyword - weak | complementary | Canonical rule, pinned candidate, `coverage/mimikatz.yml` and pinned source report. |
| Same effect split across processes, hosts or windows | Current joins/thresholds may fail | Public candidate is also bounded by its source | stable entity plus resulting security effect - moderate | longer-window rare relationship - moderate | insufficient_evidence | Analytical inference requiring local telemetry testing. |

## Missing detection branches

- Missing from ours: memory-only operation, renamed utilities, stdout output, service execution and non-default staging paths.
- Missing from public rule: complete coverage of `P01,P31,P33` and alternate implementations outside its telemetry assumptions.
- Missing from both: intent attribution and reliable detection when the necessary provider is disabled or fields are dropped.

## Detection edge cases and blind spots

Low-and-slow and distributed activity may fall outside fixed windows. Identity, process and host entities can change representation between providers. Collection loss can suppress cardinality or break ordering. Legitimate administration and security products require evidence-based trust enrichment rather than path-only exclusions.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| untrusted process creates multiple sensitive credential/ticket/hive artifact classes | strong | proposed/internal | Close to the security effect and incorporates caller/result context. | Requires detailed provider fields and local baselining. |
| procedure-specific correlation | moderate | ours | Adds ordered context but depends on stable joins and windows. | Partial telemetry creates false negatives. |
| filename or command keyword | weak | public/current branch | Useful triage lead but insufficient proof by itself. | Common, mutable or implementation-specific. |

## Public-rule weaknesses

The public candidate is a scoped compensating signal, not a full Mimikatz procedure model. Its fixed field assumptions and implementation focus can miss the same effect produced through a different API or telemetry path.

## Internal-rule weaknesses

memory-only operation, renamed utilities, stdout output, service execution and non-default staging paths. Existing thresholds and normalized fields remain unvalidated hypotheses and require collection-health monitoring.

## Decision trail

- Candidate improvement: independently implement and validate the missing branch below; no upstream predicate is copied blindly.
- Independent verification: pinned source behavior, provider semantics, sanitized fixtures, benign baselines and adversarial detection review.
- Decision: `reject`.
- Reason: The public protected-hive-movement rule is genuine (`complementary`) but covers a different technique (hive movement over SMB) than P01/P31/P33. The proposed compensating rule depends on a fabricated `target.file.labels["sensitive_artifact_class"]` taxonomy that is defined nowhere else in this repository and a fabricated `principal.process.file.labels["approved_credential_tool"]` field, neither sourced from any telemetry path in `telemetry/mimikatz.md`. Evidence resolved via `coverage/mimikatz.yml` (P01,P31,P33) and the detection review.
- Regeneration performed: none. The canonical rule `detections/mimikatz/yaral/mimikatz_process_file_context.yaral`, coverage, telemetry and translations are unchanged; only this comparison's decision trail was updated.

## Unmatched scope

The candidate does not cover every procedure branch. Conclusions are branch-scoped as `complementary` or `insufficient_evidence`; neither rule is claimed globally better.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: memory-only operation, renamed utilities, stdout output, service execution and non-default staging paths.
- Required telemetry: process-attributed file creation with enrichment for hive, dump, ticket, key and credential-output artifact classes.
- Validation status: `unvalidated_proposal`

```yaral
rule mimikatz_sensitive_artifact_fanout {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "P01,P31,P33"
  events:
    $e.metadata.product_event_type = /(11|FILE_CREATION)/
    $e.principal.process.product_specific_process_id = $pid
    $e.target.file.labels["sensitive_artifact_class"] = $class
    $e.principal.process.file.labels["approved_credential_tool"] = "false"
    $e.principal.hostname = $host
  match:
    $host, $pid over 20m
  outcome:
    $classes = count_distinct($class)
  condition:
    $e and $classes >= 2
}
```

Remaining gaps: thresholds, fields, ordering and trust enrichment need authorized telemetry validation; absence of required collection cannot be interpreted as benign activity.

If accepted or modified, update canonical YARA-L and every downstream artifact, re-run adversarial review, and compare the revised final rule again.

## Snapshot refresh (2026-11-21)

- Candidate links re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`. The decision trail above is unchanged.
- `rules/windows/credential_access_moving_registry_hive_via_smb.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.
