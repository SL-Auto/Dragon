-- source_yaral: detections/roadtools/yaral/roadtools_registered_device_default_name.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: roadtools_registered_device_default_name
-- severity: low
-- procedure_ids: RT-P03
-- description: Detects device registration or join of a device named DESKTOP- followed by seven upper-case alphanumerics where the registration was not performed by device-management enrollment (Intune or Autopilot).
-- log_source_prerequisites: Entra ID audit logs (AuditLogs) normalized with activityDisplayName in metadata.product_event_type, initiating user in principal.user.userid, target user or device in target.user.userid or target.resource.name, and modified-property values in additional.fields['modifiedProperties']; enrollment service in additional.fields['initiatedByApp'].
-- false_positives: New Windows devices registered outside Intune or Autopilot.
-- references: reports/roadtools/source-analysis.md#procedure-analysis; reviews/roadtools/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, user_id, source_ip, user_agent, app_id, resource_id, auth_protocol, incoming_token_type, result_type, device_name, initiated_by_app); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by user_id and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, user_id, source_ip, user_agent, app_id, resource_id, auth_protocol, incoming_token_type, result_type, device_name, initiated_by_app.
SELECT user_id, COUNT(*) AS matched_count, 'roadtools_registered_device_default_name' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND product_event_type IN ('Register device', 'Add device')
  AND REGEXP_LIKE(device_name, '^DESKTOP-[A-Z0-9]{7}$', 'i')
  AND NOT REGEXP_LIKE(COALESCE(initiated_by_app, ''), '(intune|autopilot|device management)', 'i')
GROUP BY user_id
HAVING COUNT(*) >= 1;
