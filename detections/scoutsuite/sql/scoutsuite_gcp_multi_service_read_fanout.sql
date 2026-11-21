-- source_yaral: detections/scoutsuite/yaral/scoutsuite_gcp_multi_service_read_fanout.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: scoutsuite_gcp_multi_service_read_fanout
-- severity: medium
-- procedure_ids: SS-P03
-- description: Detects one GCP principal issuing list, get, search or getIamPolicy calls to ten or more distinct GCP services within 30 minutes.
-- log_source_prerequisites: GCP Cloud Audit Logs Data Access with methodName in metadata.product_event_type, serviceName in target.application and principalEmail in principal.user.email_addresses.
-- false_positives: Security Command Center, CSPM and inventory service accounts.
-- references: reports/scoutsuite/source-analysis.md#procedure-analysis; reviews/scoutsuite/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, principal_email, service_name); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by principal_email and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, principal_email, service_name.
SELECT principal_email, COUNT(DISTINCT service_name) AS matched_count, 'scoutsuite_gcp_multi_service_read_fanout' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND REGEXP_LIKE(product_event_type, '\.(List|Get|Search|Aggregated|GetIamPolicy)[A-Za-z]*$|\.(list|get|search|aggregatedList|getIamPolicy)$', 'i')
GROUP BY principal_email
HAVING COUNT(DISTINCT service_name) >= 10;
