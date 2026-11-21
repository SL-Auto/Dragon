-- source_yaral: detections/cloudfox/yaral/cloudfox_aws_secret_bearing_config_sweep.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cloudfox_aws_secret_bearing_config_sweep
-- severity: high
-- procedure_ids: CF-A05
-- description: Detects one AWS principal reading three or more kinds of secret-bearing configuration within 30 minutes: instance user data, ECS task definitions, CodeBuild projects, CloudFormation templates or Lambda function configuration.
-- log_source_prerequisites: userAgent in network.http.user_agent (console traffic excluded, CF-DR-02); AWS CloudTrail management events normalized with metadata.product_name = 'AWS CloudTrail', eventName in metadata.product_event_type, eventSource in target.application, userIdentity ARN in principal.user.userid.
-- false_positives: Deployment pipelines and cloud-governance tools that read several configuration types; approve their role ARNs.
-- references: reports/cloudfox/source-analysis.md#procedure-analysis; reviews/cloudfox/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_name, product_event_type, principal_arn, event_source, source_ip, user_agent); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by principal_arn and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_name, product_event_type, principal_arn, event_source, source_ip, user_agent.
SELECT principal_arn, COUNT(DISTINCT product_event_type) AS matched_count, 'cloudfox_aws_secret_bearing_config_sweep' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND product_name = 'AWS CloudTrail'
  AND product_event_type IN ('DescribeInstanceAttribute', 'DescribeTaskDefinition', 'BatchGetProjects', 'GetTemplate', 'ListFunctions', 'GetFunctionConfiguration')
  AND NOT REGEXP_LIKE(COALESCE(user_agent, ''), '(console\.amazonaws\.com|signin\.amazonaws\.com|AWS Internal)', 'i')
GROUP BY principal_arn
HAVING COUNT(DISTINCT product_event_type) >= 3;
