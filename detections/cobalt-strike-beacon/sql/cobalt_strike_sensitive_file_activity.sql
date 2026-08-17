-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_sensitive_file_activity.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: cobalt_strike_sensitive_file_activity
-- severity: high
-- procedure_ids: CSB-024,CSB-025
-- description: Detects sensitive file read/write/rename activity followed by outbound network activity from the same process.
-- log_source_prerequisites: Normalize FILE_READ/FILE_WRITE/FILE_RENAME and process-attributed NETWORK_CONNECTION with stable process entity, path sensitivity and direction.
-- false_positives: Backup, synchronization, DLP, indexing, document management and approved transfer tools.
-- references: reports/cobalt-strike-beacon/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'cobalt_strike_sensitive_file_activity' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('FILE_READ', 'FILE_RENAME', 'FILE_WRITE', 'NETWORK_CONNECTION') OR event_type IN ('FILE_READ', 'FILE_RENAME', 'FILE_WRITE', 'NETWORK_CONNECTION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
