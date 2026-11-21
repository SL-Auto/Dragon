-- source_yaral: detections/scoutsuite/yaral/scoutsuite_aws_multi_service_read_fanout.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: scoutsuite_aws_multi_service_read_fanout
-- severity: medium
-- procedure_ids: SS-P01
-- description: Detects one non-console AWS principal issuing List, Describe or Get calls to twenty or more distinct services within 30 minutes, the breadth of a full ScoutSuite AWS audit.
-- log_source_prerequisites: AWS CloudTrail read events with eventSource in target.application and userAgent in network.http.user_agent.
-- false_positives: CSPM, inventory and governance roles.
-- references: reports/scoutsuite/source-analysis.md#procedure-analysis; reviews/scoutsuite/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, principal_arn, event_source, user_agent); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by principal_arn and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, principal_arn, event_source, user_agent.
SELECT principal_arn, COUNT(DISTINCT event_source) AS matched_count, 'scoutsuite_aws_multi_service_read_fanout' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND REGEXP_LIKE(product_event_type, '^(List|Describe|Get)[A-Z]', 'i')
  AND NOT REGEXP_LIKE(COALESCE(user_agent, ''), '(console\.amazonaws\.com|signin\.amazonaws\.com|AWS Internal)', 'i')
GROUP BY principal_arn
HAVING COUNT(DISTINCT event_source) >= 20;
