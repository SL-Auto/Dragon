-- source_yaral: detections/pacu/yaral/pacu_eventbridge_lambda_backdoor_chain.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: pacu_eventbridge_lambda_backdoor_chain
-- severity: high
-- procedure_ids: PA-P05
-- description: Detects one principal creating a Lambda function and an EventBridge rule whose event pattern matches IAM or EC2 API events within 30 minutes (PA-DR-04), the event-driven backdoor that reacts to new users, roles or security groups.
-- log_source_prerequisites: AWS CloudTrail management events normalized with metadata.product_name = 'AWS CloudTrail', eventName in metadata.product_event_type, userIdentity ARN in principal.user.userid, userAgent in network.http.user_agent and requestParameters in additional.fields; PutRule eventPattern in additional.fields['eventPattern'].
-- false_positives: Serverless deployment pipelines (CloudFormation, SAM, CDK) that create functions and rules together; approve their role ARNs.
-- references: reports/pacu/source-analysis.md#procedure-analysis; reviews/pacu/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name, event_pattern); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native ordered two-event correlation on principal_arn within 30 minutes (first event before second). Exact per-pair self-join; regex, REGEXP_SUBSTR and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name, event_pattern.
WITH first_leg AS (
  SELECT * FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
    AND product_name = 'AWS CloudTrail'
    AND REGEXP_LIKE(product_event_type, '^CreateFunction', 'i')
 ),
second_leg AS (
  SELECT * FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
    AND product_name = 'AWS CloudTrail'
    AND product_event_type = 'PutRule'
    AND REGEXP_LIKE(event_pattern, 'aws\.(iam|ec2)', 'i')
)
SELECT a.principal_arn, MIN(a.event_time) AS first_time, MAX(b.event_time) AS last_time, 'pacu_eventbridge_lambda_backdoor_chain' AS canonical_rule
FROM first_leg a
JOIN second_leg b
  ON a.principal_arn = b.principal_arn
 AND b.event_time BETWEEN a.event_time AND a.event_time + INTERVAL '30' MINUTE
GROUP BY a.principal_arn;
