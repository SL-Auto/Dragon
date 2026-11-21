-- source_yaral: detections/roadtools/yaral/roadtools_prt_cookie_legacy_user_agent.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: roadtools_prt_cookie_legacy_user_agent
-- severity: medium
-- procedure_ids: RT-P04
-- description: Detects sign-in or HTTP activity with the fixed legacy user agent ROADtools sends during PRT-cookie authentication: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E).
-- log_source_prerequisites: Entra ID sign-in logs (SigninLogs, AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs) normalized with the log name in metadata.product_event_type, UPN or service principal in principal.user.userid, IP in principal.ip, userAgent in network.http.user_agent, and appId, resourceId, authenticationProtocol, incomingTokenType, deviceId, sessionId and resultType in additional.fields; proxy NETWORK_HTTP with User-Agent where available.
-- false_positives: Legacy embedded web controls presenting compatibility user agents.
-- references: reports/roadtools/source-analysis.md#procedure-analysis; reviews/roadtools/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, user_id, source_ip, user_agent, app_id, resource_id, auth_protocol, incoming_token_type, result_type); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by user_id and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, user_id, source_ip, user_agent, app_id, resource_id, auth_protocol, incoming_token_type, result_type.
SELECT user_id, COUNT(*) AS matched_count, 'roadtools_prt_cookie_legacy_user_agent' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND REGEXP_LIKE(user_agent, 'MSIE 7\.0; Windows NT 10\.0; Win64; x64; Trident/7\.0; \.NET4\.0C; \.NET4\.0E', 'i')
GROUP BY user_id
HAVING COUNT(*) >= 1;
