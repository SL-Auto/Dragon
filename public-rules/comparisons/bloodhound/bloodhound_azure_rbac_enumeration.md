# Public-rule comparison: bloodhound_azure_rbac_enumeration

## Identity and independence gate

- Internal tool: `bloodhound`
- Internal canonical rule: `detections/bloodhound/yaral/bloodhound_azure_rbac_enumeration.yaral`
- Internal SHA-256: `877d622705c870548b10e8145bde9e49da542413e9258cb73b674e92c5118189`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `BH-019`
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate:
- [Elastic AzureHound user-agent rule](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/azure/discovery_bloodhound_user_agents_detected.toml) - pinned revision and SHA-256 `23a2c98500bd2c50247d9d802f3681598a9844e77779b0c82682d5a85773826c`.

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

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/bloodhound/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`, and canonical logic had not acted on the proposal; decided here with the evidence in hand.
- Decision: `reject`.
- Reason: the proposal is not adopted:
  - The proposal's stated gap is a single high-value scope, yet it still requires five scopes and adds an AND on three relationship types, which opens a new false-negative path (BH-DR re-review).
  - It depends on `authorization_relationship` and `scope_id` labels that no parser populates, and on a placeholder-regex comparison that is not valid YARA-L (BH-DR-30).
- Canonical result: no canonical logic changed; the proposed code is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration: none required; canonical logic is unchanged.

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

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/integrations/azure/discovery_bloodhound_user_agents_detected.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Role assignment, definition, owner and access-policy reads across many scopes | covered (>= 10 scopes over 30 minutes, including AzureActivity) | `discovery_bloodhound_user_agents_detected.toml`: AzureHound/SharpHound/BloodHound user-agent strings in Microsoft cloud logs | authorization-operation breadth - moderate | resource fan-out rule - moderate | complementary |
| Single high-value scope read | not covered | not covered | none | cloud audit of privileged role reads - weak | insufficient_evidence |
| Collector identified by its default user agent | not targeted (mutable name) | covered | user-agent string - weak (mutable) | behavioral rules - moderate | different_scope |

- Re-comparison outcome: canonical logic is unchanged; the conclusions above stand against the re-pinned candidates.
