-- source_yaral: detections/havoc/yaral/havoc_cleanup_after_network_activity.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: havoc_cleanup_after_network_activity
-- severity: medium
-- procedure_ids: HV-P20
-- description: A process deletes a file or terminates shortly after outbound network activity
-- log_source_prerequisites: EDR file deletion or process termination and process-attributed network telemetry with stable identity
-- false_positives: Installers, updaters, temporary helpers and self-cleaning applications
-- references: reports/havoc/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'havoc_cleanup_after_network_activity' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('FILE_DELETION', 'NETWORK_CONNECTION', 'PROCESS_TERMINATION') OR event_type IN ('FILE_DELETION', 'NETWORK_CONNECTION', 'PROCESS_TERMINATION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
