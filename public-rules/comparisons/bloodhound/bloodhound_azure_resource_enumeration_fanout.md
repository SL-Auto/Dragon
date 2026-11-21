# Public-rule comparison: bloodhound_azure_resource_enumeration_fanout

## Identity and independence gate

- Internal tool: `bloodhound`
- Internal canonical rule: `detections/bloodhound/yaral/bloodhound_azure_resource_enumeration_fanout.yaral`
- Internal SHA-256: `d8c57da8ec7d3da6030a375d8c985f6446236a011b21ce2bc341a09572ea1ec0`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `BH-018`
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate:
- [Elastic AzureHound user-agent rule](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/azure/discovery_bloodhound_user_agents_detected.toml) - pinned revision and SHA-256 `23a2c98500bd2c50247d9d802f3681598a9844e77779b0c82682d5a85773826c`.

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

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/bloodhound/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`, although the proposal had been copied, with divergences, into canonical YARA-L on 2026-08-16 without a recorded decision or review finding; the live rule was re-reviewed before this terminal decision.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - The adoption dropped the proposal's `subscriptions >= 2` requirement, which would have silenced single-subscription tenants, and uses `providers >= 6`.
  - The 30-minute window is kept for ARM fan-out, because the 60-minute sign-in join is carried by `bloodhound_azure_authentication_context`.
- Canonical result: `detections/bloodhound/yaral/bloodhound_azure_resource_enumeration_fanout.yaral`, SHA-256 `ff28bf2e17d48169d1d409bfb35730160532762959888a6ae15a65fef3df5d1d`.
- Regeneration: the 2026-08-16 adoption's translations, telemetry and hashes were re-verified current on 2026-11-21; no canonical change in this run.

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

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/integrations/azure/discovery_bloodhound_user_agents_detected.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| ARM reads across many provider families by one principal and application | covered | `discovery_bloodhound_user_agents_detected.toml`: AzureHound/SharpHound/BloodHound user-agent strings in Microsoft cloud logs | provider-family breadth - moderate | authentication-context rule - moderate | complementary |
| Collector identified by its default user agent | not targeted (mutable name) | covered | user-agent string - weak (mutable) | behavioral rules - moderate | different_scope |

- Current canonical YARA-L `detections/bloodhound/yaral/bloodhound_azure_resource_enumeration_fanout.yaral` (`experimental` / `needs_validation`):

```yaral
rule bloodhound_azure_resource_enumeration_fanout {
  meta:
    author = "Detection Research Agent"
    description = "Detects one principal/application reading many Azure Resource Manager provider families, independent of source IP, with subscription breadth recorded as compensating context."
    date = "2026-08-16"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Broad resource inventory provides cloud attack-path and privilege context."
    procedure_ids = "BH-018"
    log_source_prerequisites = "ARM read-plane, AzureActivity or gateway audit with principal, source, operation, provider and scope."
    false_positives = "CSPM, cloud inventory, cost management and governance automation."
    references = "reports/bloodhound/source-analysis.md, public-rules/comparisons/bloodhound/bloodhound_azure_resource_enumeration_fanout.md"
    validation_status = "needs_validation"
    validation_method = "Use sanitized resource-read fixtures and approved CSPM baselines across matching and mismatched source IPs."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/bloodhound/detection-review.md"
  events:
    $e.metadata.product_event_type = /(AzureActivity|AZURE_RESOURCE_READ)/
    $e.principal.user.userid = $principal
    $e.principal.application = $app
    $e.target.resource.attribute.labels["provider_family"] = $provider
    $e.target.resource.attribute.labels["subscription_id"] = $subscription
  match:
    $principal, $app over 30m
  outcome:
    $providers = count_distinct($provider)
    $subscriptions = count_distinct($subscription)
  condition:
    $e and $providers >= 6
}
```

- Re-comparison outcome: the current canonical rule closes the branch the proposal targeted, within declared telemetry; remaining gaps are recorded in `reviews/bloodhound/detection-review.md`.
