-- source_yaral: detections/roadtools/yaral/roadtools_passkey_default_name_registration.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: roadtools_passkey_default_name_registration
-- severity: high
-- procedure_ids: RT-P05
-- description: Detects registration of a passkey or security key whose display name is the ROADtools default (roadtx).
-- log_source_prerequisites: Entra ID audit logs (AuditLogs) normalized with activityDisplayName in metadata.product_event_type, initiating user in principal.user.userid, target user or device in target.user.userid or target.resource.name, and modified-property values in additional.fields['modifiedProperties'].
-- false_positives: A user who deliberately names a key roadtx.
-- references: reports/roadtools/source-analysis.md#procedure-analysis; reviews/roadtools/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, user_id, source_ip, user_agent, app_id, resource_id, auth_protocol, incoming_token_type, result_type, target_user, modified_properties); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by target_user and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, user_id, source_ip, user_agent, app_id, resource_id, auth_protocol, incoming_token_type, result_type, target_user, modified_properties.
SELECT target_user, COUNT(*) AS matched_count, 'roadtools_passkey_default_name_registration' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND REGEXP_LIKE(product_event_type, '(passkey|FIDO2|security info|security key)', 'i')
  AND REGEXP_LIKE(modified_properties, '\broadtx\b', 'i')
GROUP BY target_user
HAVING COUNT(*) >= 1;
