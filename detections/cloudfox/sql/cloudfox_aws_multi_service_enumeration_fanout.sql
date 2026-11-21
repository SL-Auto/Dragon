-- source_yaral: detections/cloudfox/yaral/cloudfox_aws_multi_service_enumeration_fanout.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cloudfox_aws_multi_service_enumeration_fanout
-- severity: medium
-- procedure_ids: CF-A01,CF-A02,CF-A04,CF-A06
-- description: Detects one AWS principal issuing List, Describe or Get calls to fifteen or more distinct AWS services within 30 minutes, the breadth signature of automated account enumeration.
-- log_source_prerequisites: AWS CloudTrail management events normalized with metadata.product_name = 'AWS CloudTrail', eventName in metadata.product_event_type, eventSource in target.application, userIdentity ARN in principal.user.userid; read-only management events enabled on the trail; userAgent in network.http.user_agent (console sessions excluded, CF-DR-09).
-- false_positives: CSPM, inventory, backup and cloud-governance platforms; approved security assessments. Approve their role ARNs.
-- references: reports/cloudfox/source-analysis.md#procedure-analysis; reviews/cloudfox/detection-review.md; public-rules/comparisons/cloudfox/cloudfox_aws_multi_service_enumeration_fanout.md; reviews/cloudfox/detection-review.md#cf-dr-09
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_name, product_event_type, principal_arn, event_source, source_ip, user_agent); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by principal_arn and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_name, product_event_type, principal_arn, event_source, source_ip, user_agent.
SELECT principal_arn, COUNT(DISTINCT event_source) AS matched_count, 'cloudfox_aws_multi_service_enumeration_fanout' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND product_name = 'AWS CloudTrail'
  AND REGEXP_LIKE(product_event_type, '^(List|Describe|Get)[A-Z]', 'i')
  AND NOT REGEXP_LIKE(COALESCE(user_agent, ''), '(console\.amazonaws\.com|signin\.amazonaws\.com|AWS Internal)', 'i')
GROUP BY principal_arn
HAVING COUNT(DISTINCT event_source) >= 15;
