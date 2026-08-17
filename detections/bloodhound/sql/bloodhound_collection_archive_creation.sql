-- source_yaral: detections/bloodhound/yaral/bloodhound_collection_archive_creation.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: bloodhound_collection_archive_creation
-- severity: medium
-- procedure_ids: BH-015
-- description: Correlates multiple JSON file creations with archive creation or rapid intermediate-file deletion by one process.
-- log_source_prerequisites: EDR or Sysmon file create/delete events with stable process entity, path and extension.
-- false_positives: Backup, export, packaging, browser download and administrative reporting software.
-- references: reports/bloodhound/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'bloodhound_collection_archive_creation' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('11', 'FILE_CREATION') OR event_type IN ('11', 'FILE_CREATION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
