-- source_yaral: detections/sliver/yaral/sliver_credential_file_access_from_network_process.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: sliver_credential_file_access_from_network_process
-- severity: high
-- procedure_ids: PROC-007,PROC-008
-- description: Network-active process reads or creates a well-known credential-material file
-- log_source_prerequisites: EDR file read/creation telemetry with full path, and process-attributed network telemetry, sharing a stable process entity
-- false_positives: Backup and imaging software, credential-manager and password-migration tools, EDR/AV scanners
-- references: reports/sliver/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'sliver_credential_file_access_from_network_process' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('FILE_READ', 'FILE_CREATION', 'NETWORK_CONNECTION') OR event_type IN ('FILE_READ', 'FILE_CREATION', 'NETWORK_CONNECTION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
