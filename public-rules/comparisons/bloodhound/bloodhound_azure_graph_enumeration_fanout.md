# Public-rule comparison: bloodhound_azure_graph_enumeration_fanout

## Identity and independence gate

- Internal tool: `bloodhound`
- Internal canonical rule: `detections/bloodhound/yaral/bloodhound_azure_graph_enumeration_fanout.yaral`
- Internal SHA-256: `3382a22914d15905b3e0b72a9913d7cce1a2836f4d08f631b8043e75e552269b`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `BH-017`
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate:
- [Chronicle Graph user/group enumeration rule](../../snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/graph_activity/ms_graph_user_and_group_enumeration.yaral) - pinned revision and SHA-256 `9429e64930b0f25065a9da552f6656948cf350dc7a9c8fc1aac7a66c93e093b3`.
- Additional candidate (new at refreshed revision): [Elastic Microsoft Graph application directory reconnaissance with denied requests](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/azure/discovery_graph_application_directory_reconnaissance.toml) - pinned revision and SHA-256 `b4296df85dd678c5cf73bddee9c82d7e5d312873c958dcae5a6eecf0a4d74013`. It is used only as corroborating evidence for app-only identity scoping; it was not the source of any adopted predicate.

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

- Candidate improvement: independently add the missing procedure branch shown in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned collector source, provider field semantics and the adversarial review `reviews/bloodhound/detection-review.md` (BH-DR-10 to BH-DR-25).
- Prior state: the proposal was copied into `detections/bloodhound/yaral/bloodhound_graph_deep_relationship_enumeration.yaral` on 2026-08-16 while this trail still read `deferred_pending_rule_improvement_run`, a non-terminal state the workflow now prohibits. It is re-decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real and worth a compensating rule, but the proposal as written had defects found in adversarial review. The adopted rule diverges as follows:
  - Relationship regex extended to members, appRoleAssignedTo, registeredOwners and the devices family. The proposal matched only `owners` among AzureHound's relationship endpoints (BH-DR-13; `client/groups.go#L50-L66`, `apps.go#L51`, `service_principals.go#L50`, `app_role_assignments.go#L33`, `devices.go#L50`).
  - Principal now coalesces UserId and ServicePrincipalId, because app-only collection was dropped by zero-value filtering (BH-DR-14; `config/config.go#L144-L158`).
  - Object identity captured from the request URI rather than an unpopulated `target.resource.name` (BH-DR-15).
- Canonical result: `detections/bloodhound/yaral/bloodhound_graph_deep_relationship_enumeration.yaral`, SHA-256 `9922ca50d834a24dcb584cc5a96fb6f0ceff73b79c7a6a71cd74439287bc5090`. The original proposal is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration completed in the same run: detection review, coverage ledger, `telemetry/bloodhound.md`, `telemetry/MASTER.md` counts, all five translations, translation review, dependency/manifest hashes, and the re-comparison below.
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

## Re-comparison against revised canonical rule

- Revised rule: `bloodhound_graph_deep_relationship_enumeration` (SHA-256 `9922ca50d834a24dcb584cc5a96fb6f0ceff73b79c7a6a71cd74439287bc5090`), compared on 2026-11-21 with the public candidate(s) re-pinned to the refreshed snapshots: elastic-security `9d792a8f6731542935156db61eaba88bf337e819`, chronicle-community `dbc9beb79597b519be086fce082214494d75b6a8`. Between revisions, the existing candidates changed only in metadata tags or path, with no query-logic change.

| Procedure branch / observable effect | Revised ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Per-object relationship reads (members/owners/appRoleAssignedTo/registeredOwners) | covered at >=100 objects per principal/app | Chronicle rule covers `/groups/*/members` paired with `/users` per IP/session | distinct relationship objects - strong | multi-family fanout rule - moderate | ours_stronger | Revised canonical rule, refreshed pinned candidate(s), `reviews/bloodhound/detection-review.md`. |
| App-only service-principal collection | covered via coalesced principal | Chronicle keys on IP/session; the new Elastic candidate keys on service principal with denied list-root reads | SP-scoped relationship breadth - strong | Elastic denied-read reconnaissance - moderate | complementary | Revised canonical rule, refreshed pinned candidate(s), `reviews/bloodhound/detection-review.md`. |
| Users-then-groups ordering | not required | required by the Chronicle rule | n/a | n/a | different_scope | Revised canonical rule, refreshed pinned candidate(s), `reviews/bloodhound/detection-review.md`. |

- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule bloodhound_graph_deep_relationship_enumeration {
  meta:
    author = "Detection Research Agent"
    description = "Detects one Graph user or service principal, per client application, reading relationship endpoints (members, transitiveMembers, memberOf, owners, registeredOwners, registeredUsers, appRoleAssignedTo, appRoleAssignments) for many distinct directory objects, compensating for collection that avoids the multi-family fanout captured by bloodhound_azure_graph_enumeration_fanout."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Per-object relationship reads across many groups, applications, service principals or devices expose membership and ownership attack paths as effectively as multi-family fanout."
    procedure_ids = "BH-017"
    log_source_prerequisites = "MicrosoftGraphActivityLogs with HTTP method, full request URI, AppId, and UserId or ServicePrincipalId normalized to principal.user.userid / principal.user.product_object_id."
    false_positives = "Identity governance, HR/identity synchronization, access reviews, compliance and cloud security posture tools performing legitimate per-object relationship enumeration."
    references = "reports/bloodhound/source-analysis.md#bh-017, sources/azurehound-src client/groups.go#L50-L66, client/apps.go#L51, client/service_principals.go#L50, client/app_role_assignments.go#L33, client/devices.go#L50, config/config.go#L144-L158 (23735c8), public-rules/comparisons/bloodhound/bloodhound_azure_graph_enumeration_fanout.md, reviews/bloodhound/detection-review.md#bh-dr-13"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized Graph activity fixtures for delegated and app-only principals across members/owners/appRoleAssignedTo/registeredOwners endpoints at boundary counts; baseline approved governance and sync applications."
    review_status = "reviewed"
    review_reference = "reviews/bloodhound/detection-review.md"
  events:
    $e.metadata.product_event_type = "MicrosoftGraphActivityLogs"
    $e.network.http.method = "GET"
    $e.principal.application = $app
    $principal = strings.coalesce($e.principal.user.userid, $e.principal.user.product_object_id)
    re.regex($e.target.url, `(?i)/(users|groups|servicePrincipals|applications|devices)/[^/?]+/(members|transitiveMembers|memberOf|transitiveMemberOf|owners|registeredOwners|registeredUsers|appRoleAssignedTo|appRoleAssignments)([/?]|$)`)
    $object = re.capture($e.target.url, `(?i)/(?:users|groups|servicePrincipals|applications|devices)/([^/?]+)/`)
  match:
    $principal, $app over 30m
  outcome:
    $objects = count_distinct($object)
    $source_ips = array_distinct($e.principal.ip)
  condition:
    $e and $objects >= 100
}
```

- Re-comparison outcome: the revised rule closes the branch the proposal targeted, within its declared telemetry. The remaining gaps are the accepted gaps listed in the detection review, each with a named compensating rule. No further change is proposed from this comparison.
