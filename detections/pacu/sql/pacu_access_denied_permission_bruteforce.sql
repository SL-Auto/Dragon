-- source_yaral: detections/pacu/yaral/pacu_access_denied_permission_bruteforce.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: pacu_access_denied_permission_bruteforce
-- severity: high
-- procedure_ids: PA-P02
-- description: Detects one principal receiving AccessDenied or UnauthorizedOperation errors on ten or more distinct API actions within 10 minutes, the signature of permission brute-forcing.
-- log_source_prerequisites: AWS CloudTrail management events normalized with metadata.product_name = 'AWS CloudTrail', eventName in metadata.product_event_type, userIdentity ARN in principal.user.userid, userAgent in network.http.user_agent and requestParameters in additional.fields; errorCode in additional.fields['errorCode'].
-- false_positives: Misconfigured automation after a policy change; security scanners with partial permissions.
-- references: reports/pacu/source-analysis.md#procedure-analysis; reviews/pacu/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name, error_code); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by principal_arn and threshold. Hop window approximated by scheduling every 5 minutes over the trailing 10 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name, error_code.
SELECT principal_arn, COUNT(DISTINCT product_event_type) AS matched_count, 'pacu_access_denied_permission_bruteforce' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE
  AND product_name = 'AWS CloudTrail'
  AND REGEXP_LIKE(error_code, '(AccessDenied|UnauthorizedOperation)', 'i')
GROUP BY principal_arn
HAVING COUNT(DISTINCT product_event_type) >= 10;
