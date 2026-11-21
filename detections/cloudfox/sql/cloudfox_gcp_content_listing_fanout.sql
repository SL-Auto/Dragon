-- source_yaral: detections/cloudfox/yaral/cloudfox_gcp_content_listing_fanout.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cloudfox_gcp_content_listing_fanout
-- severity: medium
-- procedure_ids: CF-G04,CF-G05
-- description: Detects one GCP principal listing log entries or bucket objects across five or more distinct logs or buckets within 30 minutes, the content-discovery sweep that precedes credential pattern matching.
-- log_source_prerequisites: GCP Cloud Audit Logs normalized with methodName in metadata.product_event_type, serviceName in target.application, resourceName in target.resource.name and principalEmail in principal.user.email_addresses; DATA_READ Data Access logs enabled for Cloud Storage and Cloud Logging.
-- false_positives: Log exporters, SIEM collectors, backup and data-catalog services.
-- references: reports/cloudfox/source-analysis.md#procedure-analysis; reviews/cloudfox/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, principal_email, resource_name); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by principal_email and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, principal_email, resource_name.
SELECT principal_email, COUNT(DISTINCT resource_name) AS matched_count, 'cloudfox_gcp_content_listing_fanout' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND REGEXP_LIKE(product_event_type, '(storage\.objects\.list|ListLogEntries)$', 'i')
GROUP BY principal_email
HAVING COUNT(DISTINCT resource_name) >= 5;
