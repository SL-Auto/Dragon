-- source_yaral: detections/pacu/yaral/pacu_s3_bulk_object_download.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: pacu_s3_bulk_object_download
-- severity: medium
-- procedure_ids: PA-P11
-- description: Detects one principal reading one hundred or more distinct S3 objects within 30 minutes (GetObject data events).
-- log_source_prerequisites: CloudTrail S3 data events (GetObject) enabled, with bucket and key in target.resource.name.
-- false_positives: Backup, replication, analytics and CDN origin roles.
-- references: reports/pacu/source-analysis.md#procedure-analysis; reviews/pacu/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by principal_arn and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name.
SELECT principal_arn, COUNT(DISTINCT resource_name) AS matched_count, 'pacu_s3_bulk_object_download' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND product_name = 'AWS CloudTrail'
  AND product_event_type = 'GetObject'
GROUP BY principal_arn
HAVING COUNT(DISTINCT resource_name) >= 100;
