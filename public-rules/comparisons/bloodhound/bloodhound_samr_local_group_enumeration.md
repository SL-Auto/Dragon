# Public-rule comparison: bloodhound_samr_local_group_enumeration

## Identity and independence gate

- Internal tool: `bloodhound`
- Internal canonical rule: `detections/bloodhound/yaral/bloodhound_samr_local_group_enumeration.yaral`
- Internal SHA-256: `23fe74320f471f57f09c0d8d7aca968e6e55ae7e1fdbf718c0fed04aa96defed`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `BH-009,BH-010`
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate:
- [Elastic privileged local-group membership discovery](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/discovery_privileged_localgroup_membership.toml) - pinned revision and SHA-256 `c38ec363024ac548dfb2660536dc763d3e37824fa962c889a7cf28160781f173`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| SAMR alias membership and LSA account-right reads across hosts | combined SAMR/LSA regex and five targets | no equivalent RPC procedure coverage | resolved SAMR alias-member or LSA account-right operation with caller process - strong | interface-only RPC connection - weak | ours_stronger | Canonical rule, pinned public candidate, `coverage/bloodhound.yml` and `reports/bloodhound/source-analysis.md`. |
| Activity is divided across identities, hosts, processes or windows | Usually falls below the current cardinality/join | Public candidate also lacks complete distributed correlation | stable entity plus procedure-specific effect - moderate | longer-window baseline/rare relationship - moderate | insufficient_evidence | This is an analytical inference requiring tenant telemetry validation. |

## Missing detection branches

- Missing from ours: different telemetry schemas for SAMR and LSA, single sensitive host, opnum-only sensors and local rights reads.
- Missing from public rule: complete ordered procedure coverage and telemetry-independent attribution beyond its declared data source.
- Missing from both: reliable intent attribution and complete observation when required logging is absent.

## Detection edge cases and blind spots

Combining interfaces hides different benign baselines and parser mappings; encrypted RPC may expose only interface UUID. Low-and-slow and distributed activity can evade fixed per-entity windows. Partial collection can reduce cardinality without indicating benign behavior. Entity normalization must distinguish user, application, process and host identities.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| resolved SAMR alias-member or LSA account-right operation with caller process | strong | ours/proposal | Close to the security-relevant collection effect and resistant to mutable filenames. | Requires the detailed telemetry declared below and authorized-tool baselining. |
| procedure-specific breadth or ordered correlation | moderate | ours | Adds behavioral context without asserting tool identity. | Thresholds and joins require local validation. |
| interface-only RPC connection | weak | public or current branch | Useful as a lead but not sufficient proof of collection. | Mutable or common in legitimate administration. |

## Public-rule weaknesses

The public candidate covers only its declared observable and does not establish the complete BloodHound collection procedure. Its implementation-specific or single-source signal can be absent while the same security effect remains observable elsewhere. It is valuable as independent compensating evidence, not authority.

## Internal-rule weaknesses

different telemetry schemas for SAMR and LSA, single sensitive host, opnum-only sensors and local rights reads. The current threshold and entity join are detection hypotheses; collection loss can silently turn a strong sequence into no alert.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown below; no public predicate is copied.
- Independent verification: compare against pinned collector source, actual provider semantics, sanitized fixtures and benign inventory baselines.
- Decision: `deferred_pending_rule_improvement_run`.
- Reason: comparison code is an unvalidated detection-engineering proposal, not canonical logic.
- Required regeneration: canonical review, coverage, telemetry, all translations, dependencies/hashes and this comparison after acceptance or modification.

## Unmatched scope

The pinned public candidate is not a complete equivalent. Branch-specific differences are retained as `ours_stronger` or `insufficient_evidence` rather than claiming either rule is globally better.

## Proposed YARA-L improvement

- Change type: `split`
- Addresses branches: different telemetry schemas for SAMR and LSA, single sensitive host, opnum-only sensors and local rights reads.
- Required telemetry: RPC interface plus resolved operation, source identity/process and target host; a separate LSA rule remains required.
- Validation status: `unvalidated_proposal`

```yaral
rule bloodhound_samr_alias_membership_fanout {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "BH-009,BH-010"
  events:
    $e.metadata.product_event_type = "RPC_CALL"
    $e.principal.hostname = $source
    $e.target.hostname = $target
    $e.target.resource.attribute.labels["rpc_interface"] = /(?i)SAMR/
    $e.target.resource.attribute.labels["rpc_operation"] = /(?i)(GetMembersInAlias|EnumerateAliases)/
  match:
    $source over 30m
  outcome:
    $targets = count_distinct($target)
  condition:
    $e and $targets >= 3
}
```

Remaining gaps: intent is not established; thresholds, normalized fields and benign baselines require authorized telemetry testing. Distributed activity and missing collection require separate compensating analytics and collection-health monitoring.

If adopted, independently revise canonical YARA-L, re-run adversarial review, reconcile telemetry and master counts, regenerate all five translations and dependencies, and re-compare the final logic.
