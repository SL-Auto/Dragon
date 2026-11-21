-- source_yaral: detections/roadtools/yaral/roadtools_foci_refresh_token_client_hopping.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: roadtools_foci_refresh_token_client_hopping
-- severity: high
-- procedure_ids: RT-P02
-- description: Detects one user obtaining tokens for four or more distinct client applications through non-interactive refresh-token sign-ins within 30 minutes, the family-of-client-IDs pivot used to expand token scope.
-- log_source_prerequisites: Entra ID sign-in logs (SigninLogs, AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs) normalized with the log name in metadata.product_event_type, UPN or service principal in principal.user.userid, IP in principal.ip, userAgent in network.http.user_agent, and appId, resourceId, authenticationProtocol, incomingTokenType, deviceId, sessionId and resultType in additional.fields.
-- false_positives: Users running several Microsoft 365 desktop apps at sign-in time; Office suite bootstrap on new devices.
-- references: reports/roadtools/source-analysis.md#procedure-analysis; reviews/roadtools/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, user_id, source_ip, user_agent, app_id, resource_id, auth_protocol, incoming_token_type, result_type); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by user_id, source_ip and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, user_id, source_ip, user_agent, app_id, resource_id, auth_protocol, incoming_token_type, result_type.
SELECT user_id, source_ip, COUNT(DISTINCT app_id) AS matched_count, 'roadtools_foci_refresh_token_client_hopping' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND product_event_type = 'AADNonInteractiveUserSignInLogs'
  AND REGEXP_LIKE(incoming_token_type, 'refreshToken', 'i')
  AND result_type = '0'
GROUP BY user_id, source_ip
HAVING COUNT(DISTINCT app_id) >= 4;
