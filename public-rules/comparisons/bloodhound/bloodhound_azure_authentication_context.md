# Public-rule comparison: bloodhound_azure_authentication_context

## Identity and independence gate

- Internal tool: `bloodhound`
- Internal canonical rule: `detections/bloodhound/yaral/bloodhound_azure_authentication_context.yaral`
- Internal SHA-256: `2a731beac5ed4490eb62ce94dc1de28ada0b73b9afa266dd5f0517f48bff6df3`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `BH-016`
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate:
- [Elastic AzureHound user-agent rule](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/azure/discovery_bloodhound_user_agents_detected.toml) - pinned revision and SHA-256 `23a2c98500bd2c50247d9d802f3681598a9844e77779b0c82682d5a85773826c`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| a cloud sign-in is followed by broad Graph or ARM reads from the same principal/source | sign-in plus twenty reads in thirty minutes | AzureHound user-agent activity without requiring sign-in correlation | app/principal-correlated authentication followed by broad read families - strong | user agent alone - weak | complementary | Canonical rule, pinned public candidate, `coverage/bloodhound.yml` and `reports/bloodhound/source-analysis.md`. |
| Activity is divided across identities, hosts, processes or windows | Usually falls below the current cardinality/join | Public candidate also lacks complete distributed correlation | stable entity plus procedure-specific effect - moderate | longer-window baseline/rare relationship - moderate | insufficient_evidence | This is an analytical inference requiring tenant telemetry validation. |

## Missing detection branches

- Missing from ours: managed identity/no sign-in, token refresh, source-IP changes, app identity joins and low-volume targeted reads.
- Missing from public rule: complete ordered procedure coverage and telemetry-independent attribution beyond its declared data source.
- Missing from both: reliable intent attribution and complete observation when required logging is absent.

## Detection edge cases and blind spots

Cloud audit delays can invert ordering; service-principal sign-ins may not share source IP with downstream gateways. Low-and-slow and distributed activity can evade fixed per-entity windows. Partial collection can reduce cardinality without indicating benign behavior. Entity normalization must distinguish user, application, process and host identities.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| app/principal-correlated authentication followed by broad read families | strong | ours/proposal | Close to the security-relevant collection effect and resistant to mutable filenames. | Requires the detailed telemetry declared below and authorized-tool baselining. |
| procedure-specific breadth or ordered correlation | moderate | ours | Adds behavioral context without asserting tool identity. | Thresholds and joins require local validation. |
| user agent alone | weak | public or current branch | Useful as a lead but not sufficient proof of collection. | Mutable or common in legitimate administration. |

## Public-rule weaknesses

The public candidate covers only its declared observable and does not establish the complete BloodHound collection procedure. Its implementation-specific or single-source signal can be absent while the same security effect remains observable elsewhere. It is valuable as independent compensating evidence, not authority.

## Internal-rule weaknesses

managed identity/no sign-in, token refresh, source-IP changes, app identity joins and low-volume targeted reads. The current threshold and entity join are detection hypotheses; collection loss can silently turn a strong sequence into no alert.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/bloodhound/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`, although the proposal had been copied, with divergences, into canonical YARA-L on 2026-08-16 without a recorded decision or review finding; the live rule was re-reviewed before this terminal decision.
- Decision: `accept`.
- Reason: the proposal closes a real branch and is adopted as written:
  - The 2026-08-16 adoption had narrowed the window to 30 minutes. Re-review restored the proposal's 60 minutes, so token-lifetime collection after the first 30 minutes joins (BH-DR-27).
  - With that change, the canonical rule equals the proposal.
- Canonical result: `detections/bloodhound/yaral/bloodhound_azure_authentication_context.yaral`, SHA-256 `569b2d4659cd3a057b4fa7da2d9be5874b8820c810ce91712035903218924072`.
- Regeneration: canonical change on 2026-11-21; detection review, `telemetry/bloodhound.md`, `telemetry/MASTER.md` counts, five translations, dependency/manifest hashes and this re-comparison were regenerated in the same run.

## Unmatched scope

The pinned public candidate is not a complete equivalent. Branch-specific differences are retained as `complementary` or `insufficient_evidence` rather than claiming either rule is globally better.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: managed identity/no sign-in, token refresh, source-IP changes, app identity joins and low-volume targeted reads.
- Required telemetry: sign-in and Graph/ARM audit with normalized principal object ID and application/service-principal ID.
- Validation status: `unvalidated_proposal`

```yaral
rule bloodhound_azure_authentication_to_enumeration {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "BH-016"
  events:
    $s.metadata.product_event_type = /(SigninLogs|AADServicePrincipalSignInLogs)/
    $s.principal.user.userid = $principal
    $s.principal.application = $app
    $r.metadata.product_event_type = /(MicrosoftGraphActivityLogs|AZURE_RESOURCE_READ)/
    $r.principal.user.userid = $principal
    $r.principal.application = $app
    $r.target.resource.attribute.labels["resource_family"] = $family
  match:
    $principal, $app over 60m
  outcome:
    $families = count_distinct($family)
  condition:
    $s and $families >= 5
}
```

Remaining gaps: intent is not established; thresholds, normalized fields and benign baselines require authorized telemetry testing. Distributed activity and missing collection require separate compensating analytics and collection-health monitoring.

If adopted, independently revise canonical YARA-L, re-run adversarial review, reconcile telemetry and master counts, regenerate all five translations and dependencies, and re-compare the final logic.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/integrations/azure/discovery_bloodhound_user_agents_detected.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Sign-in followed by broad Graph/ARM reads by the same principal and application | covered (60-minute join, >= 5 resource families) | `discovery_bloodhound_user_agents_detected.toml`: AzureHound/SharpHound/BloodHound user-agent strings in Microsoft cloud logs | sign-in plus resource-family breadth - moderate | Graph fan-out rules - moderate | complementary |
| Collector identified by its default user agent | not targeted (mutable name) | covered | user-agent string - weak (mutable) | behavioral rules - moderate | different_scope |

- Current canonical YARA-L `detections/bloodhound/yaral/bloodhound_azure_authentication_context.yaral` (`experimental` / `needs_validation`):

```yaral
rule bloodhound_azure_authentication_context {
  meta:
    author = "Detection Research Agent"
    description = "Detects a sign-in followed by broad Graph or ARM read activity from the same principal and application, independent of source IP."
    date = "2026-11-21"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "Authentication context improves correlation but is not suspicious without enumeration breadth."
    procedure_ids = "BH-016"
    log_source_prerequisites = "Entra interactive/service-principal sign-ins and Graph/ARM audit with principal user ID, application/service-principal ID and resource-family enrichment."
    false_positives = "Cloud inventory, governance, CSPM and authorized assessment."
    references = "reports/bloodhound/source-analysis.md, public-rules/comparisons/bloodhound/bloodhound_azure_authentication_context.md, reviews/bloodhound/detection-review.md#bh-dr-27"
    validation_status = "needs_validation"
    validation_method = "Use sanitized sign-in plus normal and high-breadth cloud-read fixtures across matching and mismatched source IPs."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/bloodhound/detection-review.md"
  events:
    $s.metadata.product_event_type = /(SigninLogs|AADServicePrincipalSignInLogs)/
    $s.principal.user.userid = $principal
    $s.principal.application = $app
    $r.metadata.product_event_type = /(MicrosoftGraphActivityLogs|AZURE_RESOURCE_READ)/
    $r.principal.user.userid = $principal
    $r.principal.application = $app
    $r.target.resource.attribute.labels["resource_family"] = $family
  match:
    $principal, $app over 60m
  outcome:
    $families = count_distinct($family)
  condition:
    $s and $families >= 5
}
```

- Re-comparison outcome: the current canonical rule closes the branch the proposal targeted, within declared telemetry; remaining gaps are recorded in `reviews/bloodhound/detection-review.md`.
