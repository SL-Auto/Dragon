-- source_yaral: detections/pacu/yaral/pacu_secret_value_bulk_retrieval.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: pacu_secret_value_bulk_retrieval
-- severity: high
-- procedure_ids: PA-P08
-- description: Detects one principal retrieving five or more distinct secret values within 30 minutes through Secrets Manager GetSecretValue, or SSM GetParameter(s) with decryption, excluding calls invoked by AWS services (PA-DR-09).
-- log_source_prerequisites: AWS CloudTrail management events normalized with metadata.product_name = 'AWS CloudTrail', eventName in metadata.product_event_type, userIdentity ARN in principal.user.userid, userAgent in network.http.user_agent and requestParameters in additional.fields; secretId or parameter name in target.resource.name; requestParameters.withDecryption and userIdentity.invokedBy in additional.fields.
-- false_positives: Secret-rotation tooling, migration scripts and configuration-management agents reading many parameters.
-- references: reports/pacu/source-analysis.md#procedure-analysis; reviews/pacu/detection-review.md; public-rules/comparisons/pacu/pacu_secret_value_bulk_retrieval.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name, with_decryption, invoked_by); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by principal_arn and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name, with_decryption, invoked_by.
SELECT principal_arn, COUNT(DISTINCT resource_name) AS matched_count, 'pacu_secret_value_bulk_retrieval' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND product_name = 'AWS CloudTrail'
  AND ((product_event_type IN ('GetSecretValue', 'BatchGetSecretValue')) OR (product_event_type IN ('GetParameter', 'GetParameters', 'GetParametersByPath') AND REGEXP_LIKE(with_decryption, '^true$', 'i')))
  AND NOT REGEXP_LIKE(COALESCE(invoked_by, ''), '(AWS Internal|\.amazonaws\.com)$', 'i')
GROUP BY principal_arn
HAVING COUNT(DISTINCT resource_name) >= 5;
