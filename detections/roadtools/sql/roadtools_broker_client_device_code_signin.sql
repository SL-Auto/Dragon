-- source_yaral: detections/roadtools/yaral/roadtools_broker_client_device_code_signin.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: roadtools_broker_client_device_code_signin
-- severity: high
-- procedure_ids: RT-P01,RT-P03,RT-P04
-- description: Detects successful device-code sign-ins to the Microsoft Authentication Broker client (29d9ed98-a469-4536-ade2-f981bc1d605e), the client ROADtools uses for device registration and PRT acquisition.
-- log_source_prerequisites: Entra ID sign-in logs with authenticationProtocol and appId in additional.fields, UPN in principal.user.userid.
-- false_positives: Rare administrative device-enrollment scenarios using device code with the broker.
-- references: reports/roadtools/source-analysis.md#procedure-analysis; public-rules/comparisons/roadtools/roadtools_device_code_or_ropc_signin.md; reviews/roadtools/detection-review.md#rt-dr-10
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, user_id, source_ip, user_agent, app_id, resource_id, auth_protocol, incoming_token_type, result_type); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by user_id and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, user_id, source_ip, user_agent, app_id, resource_id, auth_protocol, incoming_token_type, result_type.
SELECT user_id, COUNT(*) AS matched_count, 'roadtools_broker_client_device_code_signin' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND product_event_type IN ('SigninLogs', 'AADNonInteractiveUserSignInLogs')
  AND REGEXP_LIKE(auth_protocol, '^deviceCode$', 'i')
  AND app_id = '29d9ed98-a469-4536-ade2-f981bc1d605e'
  AND result_type = '0'
GROUP BY user_id
HAVING COUNT(*) >= 1;
