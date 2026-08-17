# Public-rule comparison: bloodhound_azure_graph_enumeration_fanout

## Identity and independence gate

- Internal tool: `bloodhound`
- Internal canonical rule: `detections/bloodhound/yaral/bloodhound_azure_graph_enumeration_fanout.yaral`
- Internal SHA-256: `3382a22914d15905b3e0b72a9913d7cce1a2836f4d08f631b8043e75e552269b`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `BH-017`
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate:
- [Chronicle Graph user/group enumeration rule](../../snapshots/chronicle-community/234e9223c3b8f3d1c30209d9663797ba69057533/rules-community/microsoft/graph_activity/ms_graph_user_and_group_enumeration.yaral) - pinned revision and SHA-256 `9429e64930b0f25065a9da552f6656948cf350dc7a9c8fc1aac7a66c93e093b3`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| one principal reads many Graph directory resource families | six normalized families in thirty minutes | specific user/group enumeration requests and known Graph reconnaissance patterns | rare app/principal enumerates multiple relationship-bearing Graph families or extreme object count - strong | one GET to users or groups - weak | complementary | Canonical rule, pinned public candidate, `coverage/bloodhound.yml` and `reports/bloodhound/source-analysis.md`. |
| Activity is divided across identities, hosts, processes or windows | Usually falls below the current cardinality/join | Public candidate also lacks complete distributed correlation | stable entity plus procedure-specific effect - moderate | longer-window baseline/rare relationship - moderate | insufficient_evidence | This is an analytical inference requiring tenant telemetry validation. |

## Missing detection branches

- Missing from ours: single-family deep enumeration, pagination volume, application/relationship endpoints, multi-IP service principals and batch requests.
- Missing from public rule: complete ordered procedure coverage and telemetry-independent attribution beyond its declared data source.
- Missing from both: reliable intent attribution and complete observation when required logging is absent.

## Detection edge cases and blind spots

Resource-family enrichment may collapse or omit paths; governance and sync applications have very broad legitimate access. Low-and-slow and distributed activity can evade fixed per-entity windows. Partial collection can reduce cardinality without indicating benign behavior. Entity normalization must distinguish user, application, process and host identities.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| rare app/principal enumerates multiple relationship-bearing Graph families or extreme object count | strong | ours/proposal | Close to the security-relevant collection effect and resistant to mutable filenames. | Requires the detailed telemetry declared below and authorized-tool baselining. |
| procedure-specific breadth or ordered correlation | moderate | ours | Adds behavioral context without asserting tool identity. | Thresholds and joins require local validation. |
| one GET to users or groups | weak | public or current branch | Useful as a lead but not sufficient proof of collection. | Mutable or common in legitimate administration. |

## Public-rule weaknesses

The public candidate covers only its declared observable and does not establish the complete BloodHound collection procedure. Its implementation-specific or single-source signal can be absent while the same security effect remains observable elsewhere. It is valuable as independent compensating evidence, not authority.

## Internal-rule weaknesses

single-family deep enumeration, pagination volume, application/relationship endpoints, multi-IP service principals and batch requests. The current threshold and entity join are detection hypotheses; collection loss can silently turn a strong sequence into no alert.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown below; no public predicate is copied.
- Independent verification: compare against pinned collector source, actual provider semantics, sanitized fixtures and benign inventory baselines.
- Decision: `deferred_pending_rule_improvement_run`.
- Reason: comparison code is an unvalidated detection-engineering proposal, not canonical logic.
- Required regeneration: canonical review, coverage, telemetry, all translations, dependencies/hashes and this comparison after acceptance or modification.

## Unmatched scope

The pinned public candidate is not a complete equivalent. Branch-specific differences are retained as `complementary` or `insufficient_evidence` rather than claiming either rule is globally better.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: single-family deep enumeration, pagination volume, application/relationship endpoints, multi-IP service principals and batch requests.
- Required telemetry: Graph audit with normalized URL, app/principal IDs and returned or targeted object identity.
- Validation status: `unvalidated_proposal`

```yaral
rule bloodhound_graph_deep_relationship_enumeration {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "BH-017"
  events:
    $e.metadata.product_event_type = "MicrosoftGraphActivityLogs"
    $e.principal.user.userid = $principal
    $e.principal.application = $app
    $e.network.http.method = "GET"
    re.regex($e.target.url, `(?i)/(users|groups|servicePrincipals|applications)/.*(memberOf|owners|appRoleAssignments|transitiveMembers)`)
    $e.target.resource.name = $object
  match:
    $principal, $app over 30m
  outcome:
    $objects = count_distinct($object)
  condition:
    $e and $objects >= 100
}
```

Remaining gaps: intent is not established; thresholds, normalized fields and benign baselines require authorized telemetry testing. Distributed activity and missing collection require separate compensating analytics and collection-health monitoring.

If adopted, independently revise canonical YARA-L, re-run adversarial review, reconcile telemetry and master counts, regenerate all five translations and dependencies, and re-compare the final logic.
