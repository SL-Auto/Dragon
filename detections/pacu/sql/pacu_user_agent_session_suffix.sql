-- source_yaral: detections/pacu/yaral/pacu_user_agent_session_suffix.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: pacu_user_agent_session_suffix
-- severity: high
-- procedure_ids: PA-P01
-- description: Detects AWS API calls whose user agent carries Pacu's session suffix (Pacu-Session-<uuid>), appended by the set_ua_suffix command.
-- log_source_prerequisites: AWS CloudTrail management events normalized with metadata.product_name = 'AWS CloudTrail', eventName in metadata.product_event_type, userIdentity ARN in principal.user.userid, userAgent in network.http.user_agent and requestParameters in additional.fields.
-- false_positives: Authorized assessments that set the suffix deliberately for deconfliction.
-- references: reports/pacu/source-analysis.md#procedure-analysis; reviews/pacu/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by principal_arn and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name.
SELECT principal_arn, COUNT(*) AS matched_count, 'pacu_user_agent_session_suffix' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND product_name = 'AWS CloudTrail'
  AND REGEXP_LIKE(user_agent, 'Pacu-Session-[0-9a-fA-F-]{36}', 'i')
GROUP BY principal_arn
HAVING COUNT(*) >= 1;
