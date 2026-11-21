# Public-rule comparison: mimikatz_protected_sam_system_access_sequence

## Identity and independence gate

- Internal tool: `mimikatz`
- Internal canonical rule: `detections/mimikatz/yaral/mimikatz_protected_sam_system_access_sequence.yaral`
- Internal SHA-256: `f6a856e4c453840e4c5534b7ceacd6ea86083692c42f13006d7c07e1117a23c7`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `P12`
- Scope mapping rationale: mapped by security effect, ordered procedure and required telemetry; names and syntax were not mapping criteria.

Public evidence:
- Behaviorally relevant public candidate: [protected hive movement](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/credential_access_moving_registry_hive_via_smb.toml) - pinned Elastic revision `7e91c156324cdc64cda27f7fec7067b1148074ef`; SHA-256 `230a77a5247b40022dcfee97a113d637644eef645137078311766a7ce252deea`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| SAM and SYSTEM/SECURITY protected hives are accessed or staged together | ordered protected-hive access sequence | hive transfer over SMB | same process reads complementary protected hives or snapshot copies - strong | single hive filename - weak | ours_stronger | Canonical rule, pinned candidate, `coverage/mimikatz.yml` and pinned source report. |
| Same effect split across processes, hosts or windows | Current joins/thresholds may fail | Public candidate is also bounded by its source | stable entity plus resulting security effect - moderate | longer-window rare relationship - moderate | insufficient_evidence | Analytical inference requiring local telemetry testing. |

## Missing detection branches

- Missing from ours: VSS/raw-volume access, registry save APIs, one hive plus boot key, alternate paths and delayed staging.
- Missing from public rule: complete coverage of `P12` and alternate implementations outside its telemetry assumptions.
- Missing from both: intent attribution and reliable detection when the necessary provider is disabled or fields are dropped.

## Detection edge cases and blind spots

Low-and-slow and distributed activity may fall outside fixed windows. Identity, process and host entities can change representation between providers. Collection loss can suppress cardinality or break ordering. Legitimate administration and security products require evidence-based trust enrichment rather than path-only exclusions.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| same process reads complementary protected hives or snapshot copies | strong | proposed/internal | Close to the security effect and incorporates caller/result context. | Requires detailed provider fields and local baselining. |
| procedure-specific correlation | moderate | ours | Adds ordered context but depends on stable joins and windows. | Partial telemetry creates false negatives. |
| single hive filename | weak | public/current branch | Useful triage lead but insufficient proof by itself. | Common, mutable or implementation-specific. |

## Public-rule weaknesses

The public candidate is a scoped compensating signal, not a full Mimikatz procedure model. Its fixed field assumptions and implementation focus can miss the same effect produced through a different API or telemetry path.

## Internal-rule weaknesses

VSS/raw-volume access, registry save APIs, one hive plus boot key, alternate paths and delayed staging. Existing thresholds and normalized fields remain unvalidated hypotheses and require collection-health monitoring.

## Decision trail

- Candidate improvement: independently implement and validate the missing branch below; no upstream predicate is copied blindly.
- Independent verification: pinned source behavior, provider semantics, sanitized fixtures, benign baselines and adversarial detection review.
- Decision: `reject`.
- Reason: Coverage conclusion is `ours_stronger` — the public rule demonstrates no capability gap here. The proposed rewrite depends on fabricated `REGISTRY_HIVE_SAVE`/`RAW_VOLUME_READ` event types and `principal.process.file.labels["approved_backup"]` / `target.file.labels["protected_hive"]` fields undocumented in `schemas/chronicle-udm.yml` or `telemetry/mimikatz.md`; the `protected_hive` label would need to duplicate exactly what the existing rule already derives directly from `target.resource.name` via regex, without evidence any real product's schema exposes it as a label. Evidence resolved via `coverage/mimikatz.yml` (P12), the canonical rule, and the detection review.
- Regeneration performed: none. The canonical rule `detections/mimikatz/yaral/mimikatz_protected_sam_system_access_sequence.yaral`, coverage, telemetry and translations are unchanged; only this comparison's decision trail was updated.

## Unmatched scope

The candidate does not cover every procedure branch. Conclusions are branch-scoped as `ours_stronger` or `insufficient_evidence`; neither rule is claimed globally better.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: VSS/raw-volume access, registry save APIs, one hive plus boot key, alternate paths and delayed staging.
- Required telemetry: registry hive save, snapshot/raw-volume or file reads with resolved hive identity and source process trust.
- Validation status: `unvalidated_proposal`

```yaral
rule mimikatz_complementary_protected_hive_access {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "P12"
  events:
    $e.metadata.product_event_type = /(REGISTRY_HIVE_SAVE|FILE_READ|RAW_VOLUME_READ)/
    $e.principal.process.product_specific_process_id = $pid
    $e.target.file.labels["protected_hive"] = $hive
    $hive = /(?i)(SAM|SYSTEM|SECURITY)/
    $e.principal.process.file.labels["approved_backup"] = "false"
    $e.principal.hostname = $host
  match:
    $host, $pid over 30m
  outcome:
    $hives = count_distinct($hive)
  condition:
    $e and $hives >= 2
}
```

Remaining gaps: thresholds, fields, ordering and trust enrichment need authorized telemetry validation; absence of required collection cannot be interpreted as benign activity.

If accepted or modified, update canonical YARA-L and every downstream artifact, re-run adversarial review, and compare the revised final rule again.

## Snapshot refresh (2026-11-21)

- Candidate links re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`. The decision trail above is unchanged.
- `rules/windows/credential_access_moving_registry_hive_via_smb.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.
