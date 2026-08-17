-- source_yaral: detections/bloodhound/yaral/bloodhound_cloud_collection_output.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: bloodhound_cloud_collection_output
-- severity: medium
-- procedure_ids: BH-020
-- description: Correlates sustained Graph or ARM reads with local JSON output or service lifecycle effects.
-- log_source_prerequisites: Process-attributed cloud egress plus file creation or Windows service events joined by host/process.
-- false_positives: Cloud inventory exporters, scheduled governance jobs and authorized AzureHound deployments.
-- references: reports/bloodhound/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'bloodhound_cloud_collection_output' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('11', '4697', '7045', 'AZURE_RESOURCE_READ', 'AzureActivity', 'FILE_CREATION', 'MicrosoftGraphActivityLogs') OR event_type IN ('11', '4697', '7045', 'AZURE_RESOURCE_READ', 'AzureActivity', 'FILE_CREATION', 'MicrosoftGraphActivityLogs')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
