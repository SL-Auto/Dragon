-- source_yaral: detections/cloudfox/yaral/cloudfox_aws_authorization_details_dump.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cloudfox_aws_authorization_details_dump
-- severity: medium
-- procedure_ids: CF-A02
-- description: Detects iam:GetAccountAuthorizationDetails, which returns every user, group, role and policy in the account in one call.
-- log_source_prerequisites: AWS CloudTrail management events normalized with metadata.product_name = 'AWS CloudTrail', eventName in metadata.product_event_type, eventSource in target.application, userIdentity ARN in principal.user.userid.
-- false_positives: IAM governance, CSPM and backup tools; approve their role ARNs.
-- references: reports/cloudfox/source-analysis.md#procedure-analysis; reviews/cloudfox/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_name, product_event_type, principal_arn, event_source, source_ip, user_agent); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by principal_arn and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_name, product_event_type, principal_arn, event_source, source_ip, user_agent.
SELECT principal_arn, COUNT(*) AS matched_count, 'cloudfox_aws_authorization_details_dump' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND product_name = 'AWS CloudTrail'
  AND product_event_type = 'GetAccountAuthorizationDetails'
GROUP BY principal_arn
HAVING COUNT(*) >= 1;
