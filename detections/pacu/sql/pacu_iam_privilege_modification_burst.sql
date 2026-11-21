-- source_yaral: detections/pacu/yaral/pacu_iam_privilege_modification_burst.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: pacu_iam_privilege_modification_burst
-- severity: high
-- procedure_ids: PA-P03,PA-P04
-- description: Detects one principal performing two or more distinct IAM privilege-modifying actions within 30 minutes: policy attachment, inline policy, default policy version, group membership or trust-policy change.
-- log_source_prerequisites: AWS CloudTrail management events normalized with metadata.product_name = 'AWS CloudTrail', eventName in metadata.product_event_type, userIdentity ARN in principal.user.userid, userAgent in network.http.user_agent and requestParameters in additional.fields.
-- false_positives: Infrastructure-as-code pipelines and identity administrators applying multi-step changes; approve deployment role ARNs.
-- references: reports/pacu/source-analysis.md#procedure-analysis; reviews/pacu/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by principal_arn and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name.
SELECT principal_arn, COUNT(DISTINCT product_event_type) AS matched_count, 'pacu_iam_privilege_modification_burst' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND product_name = 'AWS CloudTrail'
  AND product_event_type IN ('AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy', 'PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy', 'CreatePolicyVersion', 'SetDefaultPolicyVersion', 'AddUserToGroup', 'UpdateAssumeRolePolicy')
GROUP BY principal_arn
HAVING COUNT(DISTINCT product_event_type) >= 2;
