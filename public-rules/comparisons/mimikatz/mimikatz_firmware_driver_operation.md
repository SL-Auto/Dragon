# Public-rule comparison: mimikatz_firmware_driver_operation

## Identity and independence gate

- Internal tool: `mimikatz`
- Internal canonical rule: `detections/mimikatz/yaral/mimikatz_firmware_driver_operation.yaral`
- Internal SHA-256: `eacd18f37c91db14c05b428c5a956aa946a7759faccbffa2638a310d02317677`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `P39,P43`
- Scope mapping rationale: mapped by security effect, ordered procedure and required telemetry; names and syntax were not mapping criteria.

Public evidence:
- Closest public rule examined and rejected as a counterpart: [LSA security-package registration](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/persistence_via_lsa_security_support_provider_registry.toml) - pinned Elastic revision `7e91c156324cdc64cda27f7fec7067b1148074ef`; SHA-256 `251cae46baa6d8404ae10635f7b9b7b25334c6c12a2d72424143f2578fdf7140`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| firmware variables or a kernel driver expose privileged memory/hardware operations | driver/firmware operation context | No credible public counterpart in the pinned corpus; the examined LSA security-package registration rule is adjacent only and is rejected as a procedure comparator | untrusted driver load followed by privileged device or firmware variable operation - strong | driver filename or service creation alone - weak | insufficient_evidence | Canonical rule, pinned candidate, `coverage/mimikatz.yml` and pinned source report. |
| Same effect split across processes, hosts or windows | Current joins/thresholds may fail | Public candidate is also bounded by its source | stable entity plus resulting security effect - moderate | longer-window rare relationship - moderate | insufficient_evidence | Analytical inference requiring local telemetry testing. |

## Missing detection branches

- Missing from ours: driver load trust, vulnerable-driver identity, firmware write result and subsequent device access.
- Missing from public rule: complete coverage of `P39,P43` and alternate implementations outside its telemetry assumptions.
- Missing from both: intent attribution and reliable detection when the necessary provider is disabled or fields are dropped.

## Detection edge cases and blind spots

Low-and-slow and distributed activity may fall outside fixed windows. Identity, process and host entities can change representation between providers. Collection loss can suppress cardinality or break ordering. Legitimate administration and security products require evidence-based trust enrichment rather than path-only exclusions.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| untrusted driver load followed by privileged device or firmware variable operation | strong | proposed/internal | Close to the security effect and incorporates caller/result context. | Requires detailed provider fields and local baselining. |
| procedure-specific correlation | moderate | ours | Adds ordered context but depends on stable joins and windows. | Partial telemetry creates false negatives. |
| driver filename or service creation alone | weak | public/current branch | Useful triage lead but insufficient proof by itself. | Common, mutable or implementation-specific. |

## Public-rule weaknesses

No credible public counterpart was found in the pinned corpus. The cited rule was inspected because it is adjacent in the attack chain, but it does not observe the same procedure or security effect and supplies no authority for changing our logic.

## Internal-rule weaknesses

driver load trust, vulnerable-driver identity, firmware write result and subsequent device access. Existing thresholds and normalized fields remain unvalidated hypotheses and require collection-health monitoring.

## Decision trail

- Candidate improvement: independently implement and validate the missing branch below; no upstream predicate is copied blindly.
- Independent verification: pinned source behavior, provider semantics, sanitized fixtures, benign baselines and adversarial detection review.
- Decision: `reject`.
- Reason: Both matrix rows conclude `insufficient_evidence`; the examined LSA security-package rule was explicitly rejected as a non-comparator. The proposed rewrite depends on fabricated `FIRMWARE_VARIABLE_WRITE`/`DEVICE_IO_CONTROL`/`PHYSICAL_MEMORY_ACCESS` event types and a `target.file.labels["trusted_driver"]` field with no source in `schemas/chronicle-udm.yml` or `telemetry/mimikatz.md`. Evidence resolved via `coverage/mimikatz.yml` (P39,P43) and the detection review.
- Regeneration performed: none. The canonical rule `detections/mimikatz/yaral/mimikatz_firmware_driver_operation.yaral`, coverage, telemetry and translations are unchanged; only this comparison's decision trail was updated.

## Unmatched scope

The candidate does not cover every procedure branch. Conclusions are branch-scoped as `insufficient_evidence` or `insufficient_evidence`; neither rule is claimed globally better.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: driver load trust, vulnerable-driver identity, firmware write result and subsequent device access.
- Required telemetry: driver load/signature telemetry plus firmware/device/physical-memory operations correlated by driver identity.
- Validation status: `unvalidated_proposal`

```yaral
rule mimikatz_driver_to_privileged_device_operation {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "P39,P43"
  events:
    $d.metadata.product_event_type = /(6|DRIVER_LOAD)/
    $d.principal.hostname = $host
    $d.target.file.labels["trusted_driver"] = "false"
    $d.target.file.sha256 = $driver
    $o.metadata.product_event_type = /(FIRMWARE_VARIABLE_WRITE|DEVICE_IO_CONTROL|PHYSICAL_MEMORY_ACCESS)/
    $o.principal.hostname = $host
    $o.principal.process.file.sha256 = $driver
  match:
    $host, $driver over 20m
  outcome:
    $operations = count($o.metadata.id)
  condition:
    $d and $o
}
```

Remaining gaps: thresholds, fields, ordering and trust enrichment need authorized telemetry validation; absence of required collection cannot be interpreted as benign activity.

If accepted or modified, update canonical YARA-L and every downstream artifact, re-run adversarial review, and compare the revised final rule again.

## Snapshot refresh (2026-11-21)

- Candidate links re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`. The decision trail above is unchanged.
- `rules/windows/persistence_via_lsa_security_support_provider_registry.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.
