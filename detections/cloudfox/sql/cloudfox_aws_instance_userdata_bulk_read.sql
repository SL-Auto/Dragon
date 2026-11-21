-- source_yaral: detections/cloudfox/yaral/cloudfox_aws_instance_userdata_bulk_read.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cloudfox_aws_instance_userdata_bulk_read
-- severity: high
-- procedure_ids: CF-A05
-- description: Detects one AWS principal reading EC2 instance user data (DescribeInstanceAttribute with attribute userData) for three or more instances within 30 minutes, harvesting bootstrap scripts that often embed credentials.
-- log_source_prerequisites: AWS CloudTrail management events normalized with metadata.product_name = 'AWS CloudTrail', eventName in metadata.product_event_type, eventSource in target.application, userIdentity ARN in principal.user.userid; requestParameters.attribute in additional.fields['attribute'] and instanceId in target.resource.name; userIdentity.invokedBy in additional.fields['invokedBy'] (calls made by AWS services on a principal's behalf are excluded, CF-DR-10).
-- false_positives: Configuration-management or migration tooling that inspects user data; approve their role ARNs.
-- references: reports/cloudfox/source-analysis.md#procedure-analysis; reviews/cloudfox/detection-review.md; public-rules/comparisons/cloudfox/cloudfox_aws_instance_userdata_bulk_read.md; reviews/cloudfox/detection-review.md#cf-dr-10
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, request_attribute, resource_name, invoked_by); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by principal_arn and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, request_attribute, resource_name, invoked_by.
SELECT principal_arn, COUNT(DISTINCT resource_name) AS matched_count, 'cloudfox_aws_instance_userdata_bulk_read' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND product_name = 'AWS CloudTrail'
  AND product_event_type = 'DescribeInstanceAttribute'
  AND REGEXP_LIKE(request_attribute, '^userData$', 'i')
  AND NOT REGEXP_LIKE(COALESCE(invoked_by, ''), '(AWS Internal|\.amazonaws\.com)$', 'i')
GROUP BY principal_arn
HAVING COUNT(DISTINCT resource_name) >= 3;
