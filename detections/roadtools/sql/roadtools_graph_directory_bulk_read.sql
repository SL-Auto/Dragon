-- source_yaral: detections/roadtools/yaral/roadtools_graph_directory_bulk_read.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: roadtools_graph_directory_bulk_read
-- severity: medium
-- procedure_ids: RT-P10,RT-P11
-- description: Detects one identity issuing five hundred or more Microsoft Graph requests to directory endpoints (users, groups, devices, applications, servicePrincipals, directoryRoles, roleManagement, policies) within 10 minutes.
-- log_source_prerequisites: MicrosoftGraphActivityLogs with RequestUri, UserId or ServicePrincipalId in principal.user.userid.
-- false_positives: Directory synchronization, identity governance and backup applications.
-- references: reports/roadtools/source-analysis.md#procedure-analysis; reviews/roadtools/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, user_id, source_ip, user_agent, app_id, resource_id, auth_protocol, incoming_token_type, result_type, request_uri); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by user_id and threshold. Hop window approximated by scheduling every 5 minutes over the trailing 10 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, user_id, source_ip, user_agent, app_id, resource_id, auth_protocol, incoming_token_type, result_type, request_uri.
SELECT user_id, COUNT(*) AS matched_count, 'roadtools_graph_directory_bulk_read' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE
  AND product_event_type = 'MicrosoftGraphActivityLogs'
  AND REGEXP_LIKE(request_uri, '/(v1\.0|beta)/(users|groups|devices|applications|servicePrincipals|directoryRoles|roleManagement|policies)', 'i')
GROUP BY user_id
HAVING COUNT(*) >= 500;
