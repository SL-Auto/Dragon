# Public-rule comparison: mimikatz_directory_mutation

## Identity and independence gate

- Internal tool: `mimikatz`
- Internal canonical rule: `detections/mimikatz/yaral/mimikatz_directory_mutation.yaral`
- Internal SHA-256: `c886cd424273d029f50c6310783977485f84448a146038e960ea889d86463fb3`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `P15,P29`
- Scope mapping rationale: mapped by security effect, ordered procedure and required telemetry; names and syntax were not mapping criteria.

Public evidence:
- Closest public rule examined and rejected as a counterpart: [directory replication-right access](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/credential_access_dcsync_replication_rights.toml) - pinned Elastic revision `7e91c156324cdc64cda27f7fec7067b1148074ef`; SHA-256 `377bfc1f0d8db80de055524492e581dceddb326b4248640258186854f8756c83`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| DCShadow-like directory registration/write or SID-history mutation changes AD state | directory mutation events and replication context | No credible public counterpart in the pinned corpus; the examined directory replication-right access rule is adjacent only and is rejected as a procedure comparator | successful replication-related directory mutation by a non-DC identity - strong | generic 5136 modification - weak | insufficient_evidence | Canonical rule, pinned candidate, `coverage/mimikatz.yml` and pinned source report. |
| Same effect split across processes, hosts or windows | Current joins/thresholds may fail | Public candidate is also bounded by its source | stable entity plus resulting security effect - moderate | longer-window rare relationship - moderate | insufficient_evidence | Analytical inference requiring local telemetry testing. |

## Missing detection branches

- Missing from ours: rogue replication registration, SPN/object writes, SID-history change and authoritative result.
- Missing from public rule: complete coverage of `P15,P29` and alternate implementations outside its telemetry assumptions.
- Missing from both: intent attribution and reliable detection when the necessary provider is disabled or fields are dropped.

## Detection edge cases and blind spots

Low-and-slow and distributed activity may fall outside fixed windows. Identity, process and host entities can change representation between providers. Collection loss can suppress cardinality or break ordering. Legitimate administration and security products require evidence-based trust enrichment rather than path-only exclusions.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| successful replication-related directory mutation by a non-DC identity | strong | proposed/internal | Close to the security effect and incorporates caller/result context. | Requires detailed provider fields and local baselining. |
| procedure-specific correlation | moderate | ours | Adds ordered context but depends on stable joins and windows. | Partial telemetry creates false negatives. |
| generic 5136 modification | weak | public/current branch | Useful triage lead but insufficient proof by itself. | Common, mutable or implementation-specific. |

## Public-rule weaknesses

No credible public counterpart was found in the pinned corpus. The cited rule was inspected because it is adjacent in the attack chain, but it does not observe the same procedure or security effect and supplies no authority for changing our logic.

## Internal-rule weaknesses

rogue replication registration, SPN/object writes, SID-history change and authoritative result. Existing thresholds and normalized fields remain unvalidated hypotheses and require collection-health monitoring.

## Decision trail

- Candidate improvement: independently implement and validate the missing branch below; no upstream predicate is copied blindly.
- Independent verification: pinned source behavior, provider semantics, sanitized fixtures, benign baselines and adversarial detection review.
- Decision: `reject`.
- Reason: Both matrix rows conclude `insufficient_evidence`; the examined replication-right-access rule was explicitly rejected as a non-comparator for this branch. The proposed rewrite depends on a fabricated `DIRECTORY_OBJECT_MODIFY` event type and `principal.labels["is_domain_controller"]` field with no source in `schemas/chronicle-udm.yml` or `telemetry/mimikatz.md`, again matching the brittle-label pattern REVIEW-003 already removed. Evidence resolved via `coverage/mimikatz.yml` (P15,P29) and the detection review.
- Regeneration performed: none. The canonical rule `detections/mimikatz/yaral/mimikatz_directory_mutation.yaral`, coverage, telemetry and translations are unchanged; only this comparison's decision trail was updated.

## Unmatched scope

The candidate does not cover every procedure branch. Conclusions are branch-scoped as `insufficient_evidence` or `insufficient_evidence`; neither rule is claimed globally better.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: rogue replication registration, SPN/object writes, SID-history change and authoritative result.
- Required telemetry: resolved directory modifications with actor, changed attribute/value class, result and DC-identity enrichment.
- Validation status: `unvalidated_proposal`

```yaral
rule mimikatz_rogue_replication_directory_mutation {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "P15,P29"
  events:
    $e.metadata.product_event_type = /(5136|4742|DIRECTORY_OBJECT_MODIFY)/
    $e.principal.user.userid = $actor
    $e.principal.labels["is_domain_controller"] = "false"
    re.regex($e.target.resource.attribute.labels["changed_attribute"], `(?i)(servicePrincipalName|msDS-AdditionalDnsHostName|sIDHistory)`)
    $e.security_result.action = "ALLOW"
  match:
    $actor over 20m
  outcome:
    $attributes = count_distinct($e.target.resource.attribute.labels["changed_attribute"])
  condition:
    $e and $attributes >= 1
}
```

Remaining gaps: thresholds, fields, ordering and trust enrichment need authorized telemetry validation; absence of required collection cannot be interpreted as benign activity.

If accepted or modified, update canonical YARA-L and every downstream artifact, re-run adversarial review, and compare the revised final rule again.

## Snapshot refresh (2026-11-21)

- Candidate links re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`. The decision trail above is unchanged.
- `rules/windows/credential_access_dcsync_replication_rights.toml` changed between 7e91c15 and 9d792a8; re-read on 2026-11-21: the new-terms history window grew from 12h to 30h, so the rule alerts on fewer repeat principals; the replication-GUID predicate is identical. The comparison conclusions and decision are unaffected.
