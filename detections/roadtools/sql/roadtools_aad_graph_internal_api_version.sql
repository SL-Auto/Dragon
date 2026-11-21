-- source_yaral: detections/roadtools/yaral/roadtools_aad_graph_internal_api_version.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: roadtools_aad_graph_internal_api_version
-- severity: high
-- procedure_ids: RT-P11
-- description: Detects Azure AD Graph requests using the internal API versions 1.61-internal or 1.6-internal, which ROADrecon hard-codes for its directory dump.
-- log_source_prerequisites: Azure AD Graph activity logs (AADGraphActivityLogs) normalized with api-version in additional.fields['apiVersion'], caller in principal.user.userid and request URI in target.url.
-- false_positives: Legacy first-party tooling that still calls internal Azure AD Graph versions.
-- references: reports/roadtools/source-analysis.md#procedure-analysis; public-rules/comparisons/roadtools/roadtools_aad_graph_resource_token.md; reviews/roadtools/detection-review.md#rt-dr-09
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, user_id, source_ip, user_agent, app_id, resource_id, auth_protocol, incoming_token_type, result_type, api_version); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by user_id and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, user_id, source_ip, user_agent, app_id, resource_id, auth_protocol, incoming_token_type, result_type, api_version.
SELECT user_id, COUNT(*) AS matched_count, 'roadtools_aad_graph_internal_api_version' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND product_event_type = 'AADGraphActivityLogs'
  AND REGEXP_LIKE(api_version, '^1\.61?-internal$', 'i')
GROUP BY user_id
HAVING COUNT(*) >= 1;
