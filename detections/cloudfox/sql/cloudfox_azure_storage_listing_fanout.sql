-- source_yaral: detections/cloudfox/yaral/cloudfox_azure_storage_listing_fanout.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cloudfox_azure_storage_listing_fanout
-- severity: medium
-- procedure_ids: CF-Z05
-- description: Detects one identity listing containers or blobs in three or more storage accounts within 30 minutes.
-- log_source_prerequisites: StorageBlobLogs via diagnostic settings, with OperationName in metadata.product_event_type, RequesterObjectId in principal.user.userid and AccountName in target.resource.name.
-- false_positives: Backup, data-catalog and analytics services; approve their object IDs.
-- references: reports/cloudfox/source-analysis.md#procedure-analysis; reviews/cloudfox/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, requester, resource_name); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by requester and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, requester, resource_name.
SELECT requester, COUNT(DISTINCT resource_name) AS matched_count, 'cloudfox_azure_storage_listing_fanout' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND product_event_type IN ('ListContainers', 'ListBlobs')
GROUP BY requester
HAVING COUNT(DISTINCT resource_name) >= 3;
