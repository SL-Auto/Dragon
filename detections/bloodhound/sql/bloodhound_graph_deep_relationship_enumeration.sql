-- source_yaral: detections/bloodhound/yaral/bloodhound_graph_deep_relationship_enumeration.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: bloodhound_graph_deep_relationship_enumeration
-- severity: high
-- procedure_ids: BH-017
-- description: Detects one Graph user or service principal, per client application, reading relationship endpoints (members, transitiveMembers, memberOf, owners, registeredOwners, registeredUsers, appRoleAssignedTo, appRoleAssignments) for many distinct directory objects, compensating for collection that avoids the multi-family fanout captured by bloodhound_azure_graph_enumeration_fanout.
-- log_source_prerequisites: MicrosoftGraphActivityLogs with HTTP method, full request URI, AppId, and UserId or ServicePrincipalId normalized to principal.user.userid / principal.user.product_object_id.
-- false_positives: Identity governance, HR/identity synchronization, access reviews, compliance and cloud security posture tools performing legitimate per-object relationship enumeration.
-- references: reports/bloodhound/source-analysis.md#bh-017, sources/azurehound-src client/groups.go#L50-L66, client/apps.go#L51, client/service_principals.go#L50, client/app_role_assignments.go#L33, client/devices.go#L50, config/config.go#L144-L158 (23735c8), public-rules/comparisons/bloodhound/bloodhound_azure_graph_enumeration_fanout.md, reviews/bloodhound/detection-review.md#bh-dr-13
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: metadata.product_event_type->MicrosoftGraphActivityLogs table/sourcetype; network.http.method->RequestMethod/http.request.method; target.url->RequestUri/url.original; principal.user.userid->UserId; principal.user.product_object_id->ServicePrincipalId; principal.application->AppId; principal.ip->IPAddress
-- assumptions_and_gaps: Native regex filter, URI object capture, delegated/app-only principal coalesce and distinct-object threshold per principal and app. The 30m hop window is approximated by a schedule of every 10 minutes over the trailing 30 minutes. REGEXP_LIKE/REGEXP_SUBSTR and NULLIF are dialect-specific (shown in Oracle/Snowflake-style syntax).
-- Schema assumption: graph_activity(event_time, request_method, request_uri, user_id, service_principal_id, app_id, ip_address).
WITH rel AS (
  SELECT COALESCE(NULLIF(user_id, ''), NULLIF(service_principal_id, '')) AS principal,
         app_id, ip_address,
         REGEXP_SUBSTR(request_uri, '/(users|groups|servicePrincipals|applications|devices)/([^/?]+)/', 1, 1, 'i', 2) AS object_id
  FROM graph_activity
  WHERE request_method = 'GET'
    AND event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
    AND REGEXP_LIKE(request_uri, '/(users|groups|servicePrincipals|applications|devices)/[^/?]+/(members|transitiveMembers|memberOf|transitiveMemberOf|owners|registeredOwners|registeredUsers|appRoleAssignedTo|appRoleAssignments)([/?]|$)', 'i')
)
SELECT principal, app_id, COUNT(DISTINCT object_id) AS objects,
       'bloodhound_graph_deep_relationship_enumeration' AS canonical_rule
FROM rel
WHERE principal IS NOT NULL
GROUP BY principal, app_id
HAVING COUNT(DISTINCT object_id) >= 100;
