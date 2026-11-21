# Public-rule comparison: roadtools_aad_graph_resource_token

## Identity and independence gate

- Internal tool: `roadtools` (revision `792708365789be4e6f58db65c3f90701159fd0ea`)
- Internal canonical rule: `detections/roadtools/yaral/roadtools_aad_graph_resource_token.yaral`
- Internal SHA-256: `02df8757426d75e11c3c2d8019a83a4230bd98e05cf6a8906f5d6c411e58f790`
- Internal review completed before public comparison: `yes` (`reviews/roadtools/detection-review.md`, RT-DR-01 to RT-DR-08)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/azure/discovery_aad_graph_roadrecon_aiohttp_enumeration.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/azure/discovery_aad_graph_roadrecon_aiohttp_enumeration.toml) - SHA-256 `2594468574fad61446d31a418e6175af5a6564bef02e31f9a9ce19f04c6bfc75`
- Scope mapping rationale: Both detect ROADrecon's Azure AD Graph directory dump (T1087.004). The public rule uses Azure AD Graph activity logs with the internal API versions and scripting user agents; ours used token issuance for the Azure AD Graph resource.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Tokens issued for the Azure AD Graph resource | covered | not covered | token issuance - moderate | internal API version rule | ours_stronger |
| Requests using internal API versions 1.61-internal or 1.6-internal | not covered before this comparison | covered (with scripting user agent) | api-version - strong | new rule | public_stronger |
| Dump with a custom user agent | covered by the new rule (no user-agent dependency) | not covered (requires scripting user agent) | api-version - strong | none | ours_stronger |

## Missing detection branches

- Internal API-version requests were not covered (RT-DR-09).

## Detection edge cases and blind spots

- Requires the new AADGraphActivityLogs category.

## Signal-quality assessment

- Public: api-version plus user agent - strong and narrow.
- Adopted: api-version alone - strong.

## Public-rule weaknesses

- Its user-agent condition is operator-mutable.

## Internal-rule weaknesses

- The token rule fires once per session.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/roadtools/source-analysis.md`, `telemetry/roadtools.md` and `reviews/roadtools/detection-review.md`.
- Decision: `modify`.
- Reason: the branch is real; the adopted rule diverges from the proposal as follows:
  - The internal API-version branch is adopted as `roadtools_aad_graph_internal_api_version` without the public rule's user-agent condition, which ROADtools lets the operator change (RT-DR-09).
- Canonical result: `detections/roadtools/yaral/roadtools_aad_graph_internal_api_version.yaral`, SHA-256 `b3d1f1a03da67dabe6f6b358ad83a8f9b659f617d9424d3f330dba0c391ef2d0`.
- Regeneration: new canonical rule; regenerated in the same run: detection review, coverage, `telemetry/roadtools.md`, `telemetry/MASTER.md` (new AADGraphActivityLogs row), native translations, dependency and manifest hashes, and this re-comparison.

## Unmatched scope

None. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `new_rule`
- Addresses branches: Azure AD Graph requests with internal API versions.
- Required telemetry: AADGraphActivityLogs with api-version.
- Validation status: `unvalidated_proposal`

```yaral
rule roadtools_aad_graph_internal_api_with_scripting_ua {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "RT-P11"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.product_event_type = "AADGraphActivityLogs"
    re.regex($e.additional.fields["apiVersion"], `1\.61?-internal`)
    re.regex($e.network.http.user_agent, `(?i)(aiohttp|python|fasthttp)`)
  condition:
    $e
}
```

## Re-comparison against revised canonical rule

- The adopted rule was re-run against the branch matrix above on 2026-11-21. It closes the targeted branch within declared telemetry; the residual limits are in `reviews/roadtools/detection-review.md`.
- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule roadtools_aad_graph_internal_api_version {
  meta:
    author = "Detection Research Agent"
    description = "Detects Azure AD Graph requests using the internal API versions 1.61-internal or 1.6-internal, which ROADrecon hard-codes for its directory dump."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "First-party clients rarely call the internal API versions directly; the version string is fixed in the gather code (gather.py L116, L338) and does not depend on the user agent."
    procedure_ids = "RT-P11"
    log_source_prerequisites = "Azure AD Graph activity logs (AADGraphActivityLogs) normalized with api-version in additional.fields['apiVersion'], caller in principal.user.userid and request URI in target.url."
    false_positives = "Legacy first-party tooling that still calls internal Azure AD Graph versions."
    references = "reports/roadtools/source-analysis.md#procedure-analysis; public-rules/comparisons/roadtools/roadtools_aad_graph_resource_token.md; reviews/roadtools/detection-review.md#rt-dr-09"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized AADGraphActivityLogs records with api-version 1.61-internal; confirm the log category is exported."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/roadtools/detection-review.md"
  events:
    $e.metadata.product_event_type = "AADGraphActivityLogs"
    re.regex($e.additional.fields["apiVersion"], `(?i)^1\.61?-internal$`)
    $e.principal.user.userid = $principal
  match:
    $principal over 1h
  outcome:
    $requests = count($e.metadata.id)
    $user_agents = array_distinct($e.network.http.user_agent)
  condition:
    $e
}
```
