-- source_yaral: detections/sliver/yaral/sliver_cleanup_after_egress.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: sliver_cleanup_after_egress
-- severity: high
-- procedure_ids: PROC-002,PROC-026
-- description: Network process deletes its own image or related artifacts
-- log_source_prerequisites: File deletion and network telemetry with stable PID
-- false_positives: Installers, updaters, temporary utilities
-- references: reports/sliver/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'sliver_cleanup_after_egress' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('FILE_DELETION', 'NETWORK_CONNECTION') OR event_type IN ('FILE_DELETION', 'NETWORK_CONNECTION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
