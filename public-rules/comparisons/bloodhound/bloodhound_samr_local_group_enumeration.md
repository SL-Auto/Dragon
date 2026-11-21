# Public-rule comparison: bloodhound_samr_local_group_enumeration

## Identity and independence gate

- Internal tool: `bloodhound`
- Internal canonical rule: `detections/bloodhound/yaral/bloodhound_samr_local_group_enumeration.yaral`
- Internal SHA-256: `23fe74320f471f57f09c0d8d7aca968e6e55ae7e1fdbf718c0fed04aa96defed`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `BH-009,BH-010`
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate:
- [Elastic privileged local-group membership discovery](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/discovery_privileged_localgroup_membership.toml) - pinned revision and SHA-256 `7663d32868957a5dba79c065bfea1f49f5e524429fccc3500a2f07f0031f7187`.

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

- Candidate improvement: independently add the missing procedure branch shown in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned collector source, provider field semantics and the adversarial review `reviews/bloodhound/detection-review.md` (BH-DR-10 to BH-DR-25).
- Prior state: the proposal was copied into `detections/bloodhound/yaral/bloodhound_samr_alias_membership_fanout.yaral` on 2026-08-16 while this trail still read `deferred_pending_rule_improvement_run`, a non-terminal state the workflow now prohibits. It is re-decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real and worth a compensating rule, but the proposal as written had defects found in adversarial review. The adopted rule diverges as follows:
  - Procedure tag narrowed from BH-009,BH-010 to BH-009, because LSA rights reads are a different interface and stay with the combined rule (BH-DR-23).
  - Added a SAMR UUID + opnum 15/33 branch for sensors without operation names (BH-DR-22).
  - Operation predicate expressed with `re.regex`; account outcome added.
  - Single-sensitive-host branch not added: an `accepted_gap` that needs asset-criticality enrichment (BH-DR-24).
- Canonical result: `detections/bloodhound/yaral/bloodhound_samr_alias_membership_fanout.yaral`, SHA-256 `038eb0fc13c7c6d3e2318ccd7f3dcdee35ae20608221e5e39123b248701e4b3e`. The original proposal is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration completed in the same run: detection review, coverage ledger, `telemetry/bloodhound.md`, `telemetry/MASTER.md` counts, all five translations, translation review, dependency/manifest hashes, and the re-comparison below.
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

## Re-comparison against revised canonical rule

- Revised rule: `bloodhound_samr_alias_membership_fanout` (SHA-256 `038eb0fc13c7c6d3e2318ccd7f3dcdee35ae20608221e5e39123b248701e4b3e`), compared on 2026-11-21 with the public candidate(s) re-pinned to the refreshed snapshots: elastic-security `9d792a8f6731542935156db61eaba88bf337e819`, chronicle-community `dbc9beb79597b519be086fce082214494d75b6a8`. Between revisions, the existing candidates changed only in metadata tags or path, with no query-logic change.

| Procedure branch / observable effect | Revised ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| SAMR alias membership across hosts (name-resolved sensor) | covered | local net/PowerShell group-membership discovery only | resolved SAMR alias operation fanout - strong | combined SAMR/LSA rule - moderate | ours_stronger | Revised canonical rule, refreshed pinned candidate(s), `reviews/bloodhound/detection-review.md`. |
| Opnum-only RPC sensor | covered via UUID+opnum | not covered | SAMR UUID + opnum 15/33 - strong | none | ours_stronger | Revised canonical rule, refreshed pinned candidate(s), `reviews/bloodhound/detection-review.md`. |
| Single tier-0 host | not covered (accepted_gap BH-DR-24) | covers local execution on that host only | none without criticality enrichment | remote session/registry rules - moderate | complementary | Revised canonical rule, refreshed pinned candidate(s), `reviews/bloodhound/detection-review.md`. |

- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule bloodhound_samr_alias_membership_fanout {
  meta:
    author = "Detection Research Agent"
    description = "Detects SAMR alias enumeration or alias-membership reads, resolved either by SAMR operation name or by SAMR interface UUID plus opnum, against multiple remote hosts from one source, compensating for parser/vendor differences that separate SAMR from LSA policy telemetry inside the combined bloodhound_samr_local_group_enumeration regex."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "A resolved SAMR interface/operation match is more specific than the combined SAMR-or-LSA regex and reduces reliance on a single normalized label covering two distinct RPC interfaces."
    procedure_ids = "BH-009"
    log_source_prerequisites = "NDR or EDR RPC telemetry that resolves the SAMR interface (name or UUID 12345778-1234-abcd-ef00-0123456789ac) and the operation (name such as SamrEnumerateAliasesInDomain/SamrGetMembersInAlias, or opnum 15/33), plus source and target host identity."
    false_positives = "Asset inventory, compliance scanners, privileged-access management and endpoint-management systems that enumerate local group membership across hosts."
    references = "reports/bloodhound/source-analysis.md#bh-009, https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/, public-rules/comparisons/bloodhound/bloodhound_samr_local_group_enumeration.md, reviews/bloodhound/detection-review.md#bh-dr-22"
    validation_status = "needs_validation"
    validation_method = "Use sanitized SAMR alias-membership call fixtures in both name-resolved and opnum-only form, plus approved inventory negatives; verify the vendor-specific interface/operation label format before enabling."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/bloodhound/detection-review.md"
  events:
    $e.metadata.product_event_type = "RPC_CALL"
    $e.principal.hostname = $source
    $e.target.hostname = $target
    (
      (re.regex($e.target.resource.attribute.labels["rpc_interface"], `(?i)SAMR`) and re.regex($e.target.resource.attribute.labels["rpc_operation"], `(?i)(GetMembersInAlias|EnumerateAliases)`)) or
      (re.regex($e.target.resource.attribute.labels["rpc_interface"], `(?i)^12345778-1234-abcd-ef00-0123456789ac$`) and re.regex($e.target.resource.attribute.labels["rpc_opnum"], `^(15|33)$`))
    )
  match:
    $source over 30m
  outcome:
    $targets = count_distinct($target)
    $accounts = array_distinct($e.principal.user.userid)
  condition:
    $e and $targets >= 3
}
```

- Re-comparison outcome: the revised rule closes the branch the proposal targeted, within its declared telemetry. The remaining gaps are the accepted gaps listed in the detection review, each with a named compensating rule. No further change is proposed from this comparison.
