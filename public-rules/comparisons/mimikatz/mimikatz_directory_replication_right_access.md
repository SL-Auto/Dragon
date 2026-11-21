# Public-rule comparison: mimikatz_directory_replication_right_access

## Identity and independence gate

- Internal tool: `mimikatz`
- Internal canonical rule: `detections/mimikatz/yaral/mimikatz_directory_replication_right_access.yaral`
- Internal SHA-256: `77d4fc4adee33ff07a0756420f757b723ed24a1da630c2eead4c34743c8c077c`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `P14`
- Scope mapping rationale: mapped by security effect, ordered procedure and required telemetry; names and syntax were not mapping criteria.

Public evidence:
- Behaviorally relevant public candidate: [directory replication-right access](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/credential_access_dcsync_replication_rights.toml) - pinned Elastic revision `7e91c156324cdc64cda27f7fec7067b1148074ef`; SHA-256 `377bfc1f0d8db80de055524492e581dceddb326b4248640258186854f8756c83`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| a non-DC principal requests directory replication rights | replication access-right GUIDs with source/account context | same DCSync security effect using Elastic field mappings | successful replication-right access by a non-DC machine/account - strong | 4662 without property GUID resolution - weak | equivalent | Canonical rule, pinned candidate, `coverage/mimikatz.yml` and pinned source report. |
| Same effect split across processes, hosts or windows | Current joins/thresholds may fail | Public candidate is also bounded by its source | stable entity plus resulting security effect - moderate | longer-window rare relationship - moderate | insufficient_evidence | Analytical inference requiring local telemetry testing. |

## Missing detection branches

- Missing from ours: single-object targeted replication, RPC network context, DC allowlist health and identity normalization.
- Missing from public rule: complete coverage of `P14` and alternate implementations outside its telemetry assumptions.
- Missing from both: intent attribution and reliable detection when the necessary provider is disabled or fields are dropped.

## Detection edge cases and blind spots

Low-and-slow and distributed activity may fall outside fixed windows. Identity, process and host entities can change representation between providers. Collection loss can suppress cardinality or break ordering. Legitimate administration and security products require evidence-based trust enrichment rather than path-only exclusions.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| successful replication-right access by a non-DC machine/account | strong | proposed/internal | Close to the security effect and incorporates caller/result context. | Requires detailed provider fields and local baselining. |
| procedure-specific correlation | moderate | ours | Adds ordered context but depends on stable joins and windows. | Partial telemetry creates false negatives. |
| 4662 without property GUID resolution | weak | public/current branch | Useful triage lead but insufficient proof by itself. | Common, mutable or implementation-specific. |

## Public-rule weaknesses

The public candidate is a scoped compensating signal, not a full Mimikatz procedure model. Its fixed field assumptions and implementation focus can miss the same effect produced through a different API or telemetry path.

## Internal-rule weaknesses

single-object targeted replication, RPC network context, DC allowlist health and identity normalization. Existing thresholds and normalized fields remain unvalidated hypotheses and require collection-health monitoring.

## Decision trail

- Candidate improvement: independently implement and validate the missing branch below; no upstream predicate is copied blindly.
- Independent verification: pinned source behavior, provider semantics, sanitized fixtures, benign baselines and adversarial detection review.
- Decision: `reject`.
- Reason: The coverage conclusion for the primary branch is `equivalent` — the public rule demonstrates no capability we lack. The proposed rewrite adds a fabricated `principal.labels["is_domain_controller"]` field (undocumented in `schemas/chronicle-udm.yml`/`telemetry/mimikatz.md`) and requires two distinct replication-right matches within a 10-minute window, which would narrow rather than strengthen detection for the common case where a single 4662 event's description already carries both target GUIDs, with no validated benefit over the existing broad regex rule. Evidence resolved via `coverage/mimikatz.yml` (P14), the canonical rule, and the detection review.
- Regeneration performed: none. The canonical rule `detections/mimikatz/yaral/mimikatz_directory_replication_right_access.yaral`, coverage, telemetry and translations are unchanged; only this comparison's decision trail was updated.

## Unmatched scope

The candidate does not cover every procedure branch. Conclusions are branch-scoped as `equivalent` or `insufficient_evidence`; neither rule is claimed globally better.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: single-object targeted replication, RPC network context, DC allowlist health and identity normalization.
- Required telemetry: 4662 with resolved replication-right GUIDs, actor machine/account normalization, result and authoritative DC inventory.
- Validation status: `unvalidated_proposal`

```yaral
rule mimikatz_non_dc_replication_right_access {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "P14"
  events:
    $e.metadata.product_event_type = /(4662|DIRECTORY_REPLICATION_ACCESS)/
    $e.principal.user.userid = $actor
    $e.principal.labels["is_domain_controller"] = "false"
    $e.target.resource.attribute.labels["access_right"] = /(?i)(DS-Replication-Get-Changes|DS-Replication-Get-Changes-All|DS-Replication-Get-Changes-In-Filtered-Set)/
    $e.security_result.action = "ALLOW"
  match:
    $actor over 10m
  outcome:
    $rights = count_distinct($e.target.resource.attribute.labels["access_right"])
  condition:
    $e and $rights >= 2
}
```

Remaining gaps: thresholds, fields, ordering and trust enrichment need authorized telemetry validation; absence of required collection cannot be interpreted as benign activity.

If accepted or modified, update canonical YARA-L and every downstream artifact, re-run adversarial review, and compare the revised final rule again.

## Snapshot refresh (2026-11-21)

- Candidate links re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`. The decision trail above is unchanged.
- `rules/windows/credential_access_dcsync_replication_rights.toml` changed between 7e91c15 and 9d792a8; re-read on 2026-11-21: the new-terms history window grew from 12h to 30h, so the rule alerts on fewer repeat principals; the replication-GUID predicate is identical. The comparison conclusions and decision are unaffected.
