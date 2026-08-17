-- source_yaral: detections/sliver/yaral/sliver_file_activity_from_network_process.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: sliver_file_activity_from_network_process
-- severity: medium
-- procedure_ids: PROC-007,PROC-008,PROC-009
-- description: File read or mutation by an outbound-network process
-- log_source_prerequisites: EDR file and network telemetry sharing stable PID
-- false_positives: Sync, backup, browsers, package managers
-- references: reports/sliver/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'sliver_file_activity_from_network_process' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('FILE_CREATION', 'FILE_DELETION', 'FILE_MODIFICATION', 'FILE_READ', 'NETWORK_CONNECTION') OR event_type IN ('FILE_CREATION', 'FILE_DELETION', 'FILE_MODIFICATION', 'FILE_READ', 'NETWORK_CONNECTION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
