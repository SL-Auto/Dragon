-- source_yaral: detections/pacu/yaral/pacu_cognito_pool_abuse.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: pacu_cognito_pool_abuse
-- severity: medium
-- procedure_ids: PA-P14
-- description: Detects one principal performing two or more kinds of Cognito identity-creation actions within 30 minutes: CreateUserPool, CreateUserPoolClient, CreateIdentityPool, AdminCreateUser or AdminUpdateUserAttributes.
-- log_source_prerequisites: AWS CloudTrail management events normalized with metadata.product_name = 'AWS CloudTrail', eventName in metadata.product_event_type, userIdentity ARN in principal.user.userid, userAgent in network.http.user_agent and requestParameters in additional.fields.
-- false_positives: Application deployment pipelines that provision Cognito resources.
-- references: reports/pacu/source-analysis.md#procedure-analysis; reviews/pacu/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by principal_arn and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name.
SELECT principal_arn, COUNT(DISTINCT product_event_type) AS matched_count, 'pacu_cognito_pool_abuse' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND product_name = 'AWS CloudTrail'
  AND product_event_type IN ('CreateUserPool', 'CreateUserPoolClient', 'CreateIdentityPool', 'AdminCreateUser', 'AdminUpdateUserAttributes')
GROUP BY principal_arn
HAVING COUNT(DISTINCT product_event_type) >= 2;
