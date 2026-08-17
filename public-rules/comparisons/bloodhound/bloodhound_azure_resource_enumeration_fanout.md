# Public-rule comparison: bloodhound_azure_resource_enumeration_fanout

## Identity and independence gate

- Internal tool: `bloodhound`
- Internal canonical rule: `detections/bloodhound/yaral/bloodhound_azure_resource_enumeration_fanout.yaral`
- Internal SHA-256: `d8c57da8ec7d3da6030a375d8c985f6446236a011b21ce2bc341a09572ea1ec0`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `BH-018`
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate:
- [Elastic AzureHound user-agent rule](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/integrations/azure/discovery_bloodhound_user_agents_detected.toml) - pinned revision and SHA-256 `ae4b54c0bd1908c0eefc9f7b8e315a543ee1e3e5795578329fea972e02ffac60`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| one principal reads many ARM provider and scope families | six provider families tied to principal and source IP | AzureHound user-agent detection identifies implementation but not breadth | principal/app reads multiple provider families across subscriptions or management groups - strong | AzureHound user agent or six providers without rarity/baseline - weak | complementary | Canonical rule, pinned public candidate, `coverage/bloodhound.yml` and `reports/bloodhound/source-analysis.md`. |
| Activity is divided across identities, hosts, processes or windows | Usually falls below the current cardinality/join | Public candidate also lacks complete distributed correlation | stable entity plus procedure-specific effect - moderate | longer-window baseline/rare relationship - moderate | insufficient_evidence | This is an analytical inference requiring tenant telemetry validation. |

## Missing detection branches

- Missing from ours: resource-list pagination in one provider, multi-IP automation, subscription fanout and management-group traversal.
- Missing from public rule: complete ordered procedure coverage and telemetry-independent attribution beyond its declared data source.
- Missing from both: reliable intent attribution and complete observation when required logging is absent.

## Detection edge cases and blind spots

AzureActivity does not consistently contain read-plane operations; gateway coverage and provider normalization vary. Low-and-slow and distributed activity can evade fixed per-entity windows. Partial collection can reduce cardinality without indicating benign behavior. Entity normalization must distinguish user, application, process and host identities.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| principal/app reads multiple provider families across subscriptions or management groups | strong | ours/proposal | Close to the security-relevant collection effect and resistant to mutable filenames. | Requires the detailed telemetry declared below and authorized-tool baselining. |
| procedure-specific breadth or ordered correlation | moderate | ours | Adds behavioral context without asserting tool identity. | Thresholds and joins require local validation. |
| AzureHound user agent or six providers without rarity/baseline | weak | public or current branch | Useful as a lead but not sufficient proof of collection. | Mutable or common in legitimate administration. |

## Public-rule weaknesses

The public candidate covers only its declared observable and does not establish the complete BloodHound collection procedure. Its implementation-specific or single-source signal can be absent while the same security effect remains observable elsewhere. It is valuable as independent compensating evidence, not authority.

## Internal-rule weaknesses

resource-list pagination in one provider, multi-IP automation, subscription fanout and management-group traversal. The current threshold and entity join are detection hypotheses; collection loss can silently turn a strong sequence into no alert.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown below; no public predicate is copied.
- Independent verification: compare against pinned collector source, actual provider semantics, sanitized fixtures and benign inventory baselines.
- Decision: `deferred_pending_rule_improvement_run`.
- Reason: comparison code is an unvalidated detection-engineering proposal, not canonical logic.
- Required regeneration: canonical review, coverage, telemetry, all translations, dependencies/hashes and this comparison after acceptance or modification.

## Unmatched scope

The pinned public candidate is not a complete equivalent. Branch-specific differences are retained as `complementary` or `insufficient_evidence` rather than claiming either rule is globally better.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: resource-list pagination in one provider, multi-IP automation, subscription fanout and management-group traversal.
- Required telemetry: ARM read-plane audit with app/principal, provider family and subscription/management scope.
- Validation status: `unvalidated_proposal`

```yaral
rule bloodhound_arm_scope_and_provider_fanout {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "BH-018"
  events:
    $e.metadata.product_event_type = /(?i)(AZURE_RESOURCE_READ|AzureActivity)/
    $e.principal.user.userid = $principal
    $e.principal.application = $app
    $e.target.resource.attribute.labels["provider_family"] = $provider
    $e.target.resource.attribute.labels["subscription_id"] = $subscription
  match:
    $principal, $app over 60m
  outcome:
    $providers = count_distinct($provider)
    $subscriptions = count_distinct($subscription)
  condition:
    $e and $providers >= 5 and $subscriptions >= 2
}
```

Remaining gaps: intent is not established; thresholds, normalized fields and benign baselines require authorized telemetry testing. Distributed activity and missing collection require separate compensating analytics and collection-health monitoring.

If adopted, independently revise canonical YARA-L, re-run adversarial review, reconcile telemetry and master counts, regenerate all five translations and dependencies, and re-compare the final logic.
