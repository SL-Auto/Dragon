# Public-rule comparison: mimikatz_certificate_key_operation

## Identity and independence gate

- Internal tool: `mimikatz`
- Internal canonical rule: `detections/mimikatz/yaral/mimikatz_certificate_key_operation.yaral`
- Internal SHA-256: `39296843f310966618927031ca6d63dee34b643600e1f101d4dc7f08ecfdc28c`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `P21,P24`
- Scope mapping rationale: mapped by security effect, ordered procedure and required telemetry; names and syntax were not mapping criteria.

Public evidence:
- Closest public rule examined and rejected as a counterpart: [DPAPI domain backup-key access](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/credential_access_domain_backup_dpapi_private_keys.toml) - pinned Elastic revision `7e91c156324cdc64cda27f7fec7067b1148074ef`; SHA-256 `b69707ba64c8a361e1ca8834e3bb0ff0f970c9e5eab4ae3e61f7cbf63a1e43ae`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| certificate enrollment or Hello key material is exported, moved or accessed | certificate/key operation activity | No credible public counterpart in the pinned corpus; the examined DPAPI domain backup-key access rule is adjacent only and is rejected as a procedure comparator | successful non-exportable private-key export or NGC key-container read by an untrusted process - strong | certificate API use - weak | insufficient_evidence | Canonical rule, pinned candidate, `coverage/mimikatz.yml` and pinned source report. |
| Same effect split across processes, hosts or windows | Current joins/thresholds may fail | Public candidate is also bounded by its source | stable entity plus resulting security effect - moderate | longer-window rare relationship - moderate | insufficient_evidence | Analytical inference requiring local telemetry testing. |

## Missing detection branches

- Missing from ours: private-key export result, key provider, caller process, Hello container access.
- Missing from public rule: complete coverage of `P21,P24` and alternate implementations outside its telemetry assumptions.
- Missing from both: intent attribution and reliable detection when the necessary provider is disabled or fields are dropped.

## Detection edge cases and blind spots

Low-and-slow and distributed activity may fall outside fixed windows. Identity, process and host entities can change representation between providers. Collection loss can suppress cardinality or break ordering. Legitimate administration and security products require evidence-based trust enrichment rather than path-only exclusions.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| successful non-exportable private-key export or NGC key-container read by an untrusted process | strong | proposed/internal | Close to the security effect and incorporates caller/result context. | Requires detailed provider fields and local baselining. |
| procedure-specific correlation | moderate | ours | Adds ordered context but depends on stable joins and windows. | Partial telemetry creates false negatives. |
| certificate API use | weak | public/current branch | Useful triage lead but insufficient proof by itself. | Common, mutable or implementation-specific. |

## Public-rule weaknesses

No credible public counterpart was found in the pinned corpus. The cited rule was inspected because it is adjacent in the attack chain, but it does not observe the same procedure or security effect and supplies no authority for changing our logic.

## Internal-rule weaknesses

private-key export result, key provider, caller process, Hello container access. Existing thresholds and normalized fields remain unvalidated hypotheses and require collection-health monitoring.

## Decision trail

- Candidate improvement: independently implement and validate the missing branch below; no upstream predicate is copied blindly.
- Independent verification: pinned source behavior, provider semantics, sanitized fixtures, benign baselines and adversarial detection review.
- Decision: `reject`.
- Reason: Both matrix rows conclude `insufficient_evidence`; no credible public rule was found for this branch (the examined DPAPI domain backup-key rule was explicitly rejected as a non-comparator). The proposed compensating rule depends on `metadata.product_event_type` literals (`CAPI2_KEY_EXPORT`, `NGC_KEY_ACCESS`, `CRYPTO_KEY_EXPORT`) and `principal.process.file.labels["trusted_key_manager"]` / `target.resource.attribute.labels["key_exportable"]` fields that are undocumented in `schemas/chronicle-udm.yml` and `telemetry/mimikatz.md`, and unsupported by any telemetry path in `reports/mimikatz/source-analysis.md`. Per `reviews/mimikatz/detection-review.md` REVIEW-003/REVIEW-006, invented trust labels and unverified structured fields are exactly the pattern already found unsafe and either removed or held as `accepted_gap`. Evidence resolved via `coverage/mimikatz.yml` (P21,P24), `telemetry/mimikatz.md`, and the detection review.
- Regeneration performed: none. The canonical rule `detections/mimikatz/yaral/mimikatz_certificate_key_operation.yaral`, coverage, telemetry and translations are unchanged; only this comparison's decision trail was updated.

## Unmatched scope

The candidate does not cover every procedure branch. Conclusions are branch-scoped as `insufficient_evidence` or `insufficient_evidence`; neither rule is claimed globally better.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: private-key export result, key provider, caller process, Hello container access.
- Required telemetry: CAPI2/crypto provider and NGC key access with export result, key properties and caller process trust.
- Validation status: `unvalidated_proposal`

```yaral
rule mimikatz_private_key_export_or_ngc_access {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "P21,P24"
  events:
    $e.metadata.product_event_type = /(CAPI2_KEY_EXPORT|NGC_KEY_ACCESS|CRYPTO_KEY_EXPORT)/
    $e.principal.process.file.labels["trusted_key_manager"] = "false"
    $e.target.resource.attribute.labels["key_exportable"] = "false"
    $e.security_result.action = "ALLOW"
    $e.principal.hostname = $host
  match:
    $host over 15m
  outcome:
    $operations = count($e.metadata.id)
  condition:
    $e and $operations >= 1
}
```

Remaining gaps: thresholds, fields, ordering and trust enrichment need authorized telemetry validation; absence of required collection cannot be interpreted as benign activity.

If accepted or modified, update canonical YARA-L and every downstream artifact, re-run adversarial review, and compare the revised final rule again.
