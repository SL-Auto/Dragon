-- source_yaral: detections/cloudfox/yaral/cloudfox_aws_policy_simulation_fanout.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cloudfox_aws_policy_simulation_fanout
-- severity: medium
-- procedure_ids: CF-A03
-- description: Detects one AWS principal calling iam:SimulatePrincipalPolicy for three or more distinct principals within 30 minutes, computing which identities can perform sensitive actions.
-- log_source_prerequisites: AWS CloudTrail management events normalized with metadata.product_name = 'AWS CloudTrail', eventName in metadata.product_event_type, eventSource in target.application, userIdentity ARN in principal.user.userid; requestParameters.policySourceArn in target.resource.name.
-- false_positives: IAM Access Analyzer-style governance tools and policy test pipelines.
-- references: reports/cloudfox/source-analysis.md#procedure-analysis; reviews/cloudfox/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by principal_arn and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name.
SELECT principal_arn, COUNT(DISTINCT resource_name) AS matched_count, 'cloudfox_aws_policy_simulation_fanout' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND product_name = 'AWS CloudTrail'
  AND product_event_type = 'SimulatePrincipalPolicy'
GROUP BY principal_arn
HAVING COUNT(DISTINCT resource_name) >= 3;
