# Public-rule comparison: bloodhound_azure_rbac_enumeration

## Identity and independence gate

- Internal tool: `bloodhound`
- Internal canonical rule: `detections/bloodhound/yaral/bloodhound_azure_rbac_enumeration.yaral`
- Internal SHA-256: `877d622705c870548b10e8145bde9e49da542413e9258cb73b674e92c5118189`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `BH-019`
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate:
- [Elastic AzureHound user-agent rule](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/integrations/azure/discovery_bloodhound_user_agents_detected.toml) - pinned revision and SHA-256 `ae4b54c0bd1908c0eefc9f7b8e315a543ee1e3e5795578329fea972e02ffac60`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| principal reads RBAC assignments, definitions, ownership, policy or eligibility across scopes | operation regex and ten distinct scopes | AzureHound user-agent rule gives implementation attribution but does not isolate RBAC | rare principal/app reads multiple authorization relationship types across sensitive scopes - strong | ten scope names without resource sensitivity or result context - weak | ours_stronger | Canonical rule, pinned public candidate, `coverage/bloodhound.yml` and `reports/bloodhound/source-analysis.md`. |
| Activity is divided across identities, hosts, processes or windows | Usually falls below the current cardinality/join | Public candidate also lacks complete distributed correlation | stable entity plus procedure-specific effect - moderate | longer-window baseline/rare relationship - moderate | insufficient_evidence | This is an analytical inference requiring tenant telemetry validation. |

## Missing detection branches

- Missing from ours: single high-value scope, Graph role-management endpoints, pagination, inherited assignments and multi-subscription distribution.
- Missing from public rule: complete ordered procedure coverage and telemetry-independent attribution beyond its declared data source.
- Missing from both: reliable intent attribution and complete observation when required logging is absent.

## Detection edge cases and blind spots

Generic owners matching may include unrelated APIs; approved access-review platforms legitimately have high cardinality. Low-and-slow and distributed activity can evade fixed per-entity windows. Partial collection can reduce cardinality without indicating benign behavior. Entity normalization must distinguish user, application, process and host identities.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| rare principal/app reads multiple authorization relationship types across sensitive scopes | strong | ours/proposal | Close to the security-relevant collection effect and resistant to mutable filenames. | Requires the detailed telemetry declared below and authorized-tool baselining. |
| procedure-specific breadth or ordered correlation | moderate | ours | Adds behavioral context without asserting tool identity. | Thresholds and joins require local validation. |
| ten scope names without resource sensitivity or result context | weak | public or current branch | Useful as a lead but not sufficient proof of collection. | Mutable or common in legitimate administration. |

## Public-rule weaknesses

The public candidate covers only its declared observable and does not establish the complete BloodHound collection procedure. Its implementation-specific or single-source signal can be absent while the same security effect remains observable elsewhere. It is valuable as independent compensating evidence, not authority.

## Internal-rule weaknesses

single high-value scope, Graph role-management endpoints, pagination, inherited assignments and multi-subscription distribution. The current threshold and entity join are detection hypotheses; collection loss can silently turn a strong sequence into no alert.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown below; no public predicate is copied.
- Independent verification: compare against pinned collector source, actual provider semantics, sanitized fixtures and benign inventory baselines.
- Decision: `deferred_pending_rule_improvement_run`.
- Reason: comparison code is an unvalidated detection-engineering proposal, not canonical logic.
- Required regeneration: canonical review, coverage, telemetry, all translations, dependencies/hashes and this comparison after acceptance or modification.

## Unmatched scope

The pinned public candidate is not a complete equivalent. Branch-specific differences are retained as `ours_stronger` or `insufficient_evidence` rather than claiming either rule is globally better.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: single high-value scope, Graph role-management endpoints, pagination, inherited assignments and multi-subscription distribution.
- Required telemetry: Graph/ARM read audit enriched to authorization relationship type, stable app/principal and scope IDs.
- Validation status: `unvalidated_proposal`

```yaral
rule bloodhound_azure_authorization_relationship_enumeration {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "BH-019"
  events:
    $e.metadata.product_event_type = /(MicrosoftGraphActivityLogs|AZURE_RESOURCE_READ)/
    $e.principal.user.userid = $principal
    $e.principal.application = $app
    $e.target.resource.attribute.labels["authorization_relationship"] = $relationship
    $relationship = /(?i)(role_assignment|role_definition|owner|access_policy|eligibility)/
    $e.target.resource.attribute.labels["scope_id"] = $scope
  match:
    $principal, $app over 60m
  outcome:
    $relationships = count_distinct($relationship)
    $scopes = count_distinct($scope)
  condition:
    $e and $relationships >= 3 and $scopes >= 5
}
```

Remaining gaps: intent is not established; thresholds, normalized fields and benign baselines require authorized telemetry testing. Distributed activity and missing collection require separate compensating analytics and collection-health monitoring.

If adopted, independently revise canonical YARA-L, re-run adversarial review, reconcile telemetry and master counts, regenerate all five translations and dependencies, and re-compare the final logic.
