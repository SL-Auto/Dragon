# Public-rule comparison: mimikatz_sensitive_store_access

## Identity and independence gate

- Internal tool: `mimikatz`
- Internal canonical rule: `detections/mimikatz/yaral/mimikatz_sensitive_store_access.yaral`
- Internal SHA-256: `e1f61851fd7cdaf8a7a1c774e8869901322a43f4e86232cc8c45974e1f7e3aa3`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `P18,P19,P20,P23,P25,P37,P41,P46`
- Scope mapping rationale: mapped by security effect, ordered procedure and required telemetry; names and syntax were not mapping criteria.

Public evidence:
- Behaviorally relevant public candidate: [DPAPI domain backup-key access](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/credential_access_domain_backup_dpapi_private_keys.toml) - pinned Elastic revision `7e91c156324cdc64cda27f7fec7067b1148074ef`; SHA-256 `b69707ba64c8a361e1ca8834e3bb0ff0f970c9e5eab4ae3e61f7cbf63a1e43ae`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| credential managers, DPAPI stores, Vault, browser/app or protected key stores are read/exported | broad sensitive-store access | domain DPAPI backup-key access | untrusted process successfully accesses multiple independent credential-store families - strong | one file/registry path read - weak | complementary | Canonical rule, pinned candidate, `coverage/mimikatz.yml` and pinned source report. |
| Same effect split across processes, hosts or windows | Current joins/thresholds may fail | Public candidate is also bounded by its source | stable entity plus resulting security effect - moderate | longer-window rare relationship - moderate | insufficient_evidence | Analytical inference requiring local telemetry testing. |

## Missing detection branches

- Missing from ours: store-specific APIs, result, caller process, multiple store families and local versus domain key paths.
- Missing from public rule: complete coverage of `P18,P19,P20,P23,P25,P37,P41,P46` and alternate implementations outside its telemetry assumptions.
- Missing from both: intent attribution and reliable detection when the necessary provider is disabled or fields are dropped.

## Detection edge cases and blind spots

Low-and-slow and distributed activity may fall outside fixed windows. Identity, process and host entities can change representation between providers. Collection loss can suppress cardinality or break ordering. Legitimate administration and security products require evidence-based trust enrichment rather than path-only exclusions.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| untrusted process successfully accesses multiple independent credential-store families | strong | proposed/internal | Close to the security effect and incorporates caller/result context. | Requires detailed provider fields and local baselining. |
| procedure-specific correlation | moderate | ours | Adds ordered context but depends on stable joins and windows. | Partial telemetry creates false negatives. |
| one file/registry path read | weak | public/current branch | Useful triage lead but insufficient proof by itself. | Common, mutable or implementation-specific. |

## Public-rule weaknesses

The public candidate is a scoped compensating signal, not a full Mimikatz procedure model. Its fixed field assumptions and implementation focus can miss the same effect produced through a different API or telemetry path.

## Internal-rule weaknesses

store-specific APIs, result, caller process, multiple store families and local versus domain key paths. Existing thresholds and normalized fields remain unvalidated hypotheses and require collection-health monitoring.

## Decision trail

- Candidate improvement: independently implement and validate the missing branch below; no upstream predicate is copied blindly.
- Independent verification: pinned source behavior, provider semantics, sanitized fixtures, benign baselines and adversarial detection review.
- Decision: `modify`.
- Reason: Accept the identified gap — the branch itself is real and evidenced by the public DPAPI domain backup-key rule (`complementary`), and this comparison's own signal-quality table already ranks "untrusted process successfully accesses multiple independent credential-store families" as `strong` versus "one file/registry path read" as `weak`. Reject the specific proposed implementation: `metadata.product_event_type` values `CREDENTIAL_STORE_ACCESS`/`DPAPI_KEY_ACCESS` and `target.resource.attribute.labels["credential_store_family"]` / `principal.process.file.labels["approved_credential_manager"]` are undocumented in `schemas/chronicle-udm.yml` and `telemetry/mimikatz.md` and unsupported by `reports/mimikatz/source-analysis.md`. The gap is independently reimplemented using only fields already established elsewhere in this ruleset (`metadata.event_type`, `target.resource.name` regex over the same family groups already used in the existing broad rule, `principal.hostname`/`principal.process.product_specific_process_id`/`principal.user.userid` joined over 15m — the same join pattern already validated in `mimikatz_protected_sam_system_access_sequence`), avoiding every fabricated field in the original proposal.
- Regeneration performed: added new canonical rule `detections/mimikatz/yaral/mimikatz_sensitive_store_multi_family_access.yaral` (additive; the original broad `mimikatz_sensitive_store_access` rule is unchanged); adversarial review recorded as REVIEW-010 in `reviews/mimikatz/detection-review.md`; `coverage/mimikatz.yml` reconciled to add the new rule against P18,P19,P20,P23,P25,P37,P41,P46; `telemetry/mimikatz.md` rule-by-rule table updated with a new row; all 5 secondary translations generated under `detections/mimikatz/{spl,kql,sql,eql,sigma}/mimikatz_sensitive_store_multi_family_access.*` with `source_yaral`, `translation_status` and `fidelity: partial` recorded; `dependencies/mimikatz/*.yml` and `manifests/mimikatz.yml` refreshed via `scripts/update-context-index.ps1`.

## Unmatched scope

The candidate does not cover every procedure branch. Conclusions are branch-scoped as `complementary` or `insufficient_evidence`; neither rule is claimed globally better.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: store-specific APIs, result, caller process, multiple store families and local versus domain key paths.
- Required telemetry: store/API-specific access with result, stable process entity and normalized credential-store family.
- Validation status: `unvalidated_proposal`

```yaral
rule mimikatz_multi_store_credential_access {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "P18,P19,P20,P23,P25,P37,P41,P46"
  events:
    $e.metadata.product_event_type = /(CREDENTIAL_STORE_ACCESS|FILE_READ|REGISTRY_READ|DPAPI_KEY_ACCESS)/
    $e.principal.process.product_specific_process_id = $pid
    $e.target.resource.attribute.labels["credential_store_family"] = $store
    $e.security_result.action = "ALLOW"
    $e.principal.process.file.labels["approved_credential_manager"] = "false"
    $e.principal.hostname = $host
  match:
    $host, $pid over 20m
  outcome:
    $stores = count_distinct($store)
  condition:
    $e and $stores >= 2
}
```

Remaining gaps: thresholds, fields, ordering and trust enrichment need authorized telemetry validation; absence of required collection cannot be interpreted as benign activity.

If accepted or modified, update canonical YARA-L and every downstream artifact, re-run adversarial review, and compare the revised final rule again.
