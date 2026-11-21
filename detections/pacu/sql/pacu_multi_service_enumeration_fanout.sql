-- source_yaral: detections/pacu/yaral/pacu_multi_service_enumeration_fanout.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: pacu_multi_service_enumeration_fanout
-- severity: medium
-- procedure_ids: PA-P02,PA-P11,PA-P16
-- description: Detects one non-console AWS principal issuing List, Describe or Get calls to fifteen or more distinct services within 30 minutes, the breadth of Pacu's enumeration modules.
-- log_source_prerequisites: AWS CloudTrail management events normalized with metadata.product_name = 'AWS CloudTrail', eventName in metadata.product_event_type, userIdentity ARN in principal.user.userid, userAgent in network.http.user_agent and requestParameters in additional.fields; eventSource in target.application.
-- false_positives: CSPM, inventory and governance roles.
-- references: reports/pacu/source-analysis.md#procedure-analysis; reviews/pacu/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by principal_arn and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name.
SELECT principal_arn, COUNT(DISTINCT event_source) AS matched_count, 'pacu_multi_service_enumeration_fanout' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND product_name = 'AWS CloudTrail'
  AND REGEXP_LIKE(product_event_type, '^(List|Describe|Get)[A-Z]', 'i')
  AND NOT REGEXP_LIKE(COALESCE(user_agent, ''), '(console\.amazonaws\.com|signin\.amazonaws\.com|AWS Internal)', 'i')
GROUP BY principal_arn
HAVING COUNT(DISTINCT event_source) >= 15;
