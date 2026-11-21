-- source_yaral: detections/pacu/yaral/pacu_log_formula_injection.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: pacu_log_formula_injection
-- severity: medium
-- procedure_ids: PA-P13
-- description: Detects CreateTrail or RunInstances requests whose name or tag value begins with a spreadsheet formula character (=, +, -, @), used to inject formulas into exported CloudTrail logs.
-- log_source_prerequisites: AWS CloudTrail management events normalized with metadata.product_name = 'AWS CloudTrail', eventName in metadata.product_event_type, userIdentity ARN in principal.user.userid, userAgent in network.http.user_agent and requestParameters in additional.fields; trail name or tag values in additional.fields['name'].
-- false_positives: None expected; a leading hyphen in names is occasionally used.
-- references: reports/pacu/source-analysis.md#procedure-analysis; reviews/pacu/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name, request_name); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by principal_arn and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name, request_name.
SELECT principal_arn, COUNT(*) AS matched_count, 'pacu_log_formula_injection' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND product_name = 'AWS CloudTrail'
  AND product_event_type IN ('CreateTrail', 'RunInstances')
  AND REGEXP_LIKE(request_name, '^\s*[=+@]|^\s*-[^-\s]', 'i')
GROUP BY principal_arn
HAVING COUNT(*) >= 1;
