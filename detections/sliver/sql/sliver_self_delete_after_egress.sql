-- source_yaral: detections/sliver/yaral/sliver_self_delete_after_egress.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: sliver_self_delete_after_egress
-- severity: high
-- procedure_ids: PROC-002,PROC-026
-- description: A process with outbound network activity deletes a file matching its own executable hash
-- log_source_prerequisites: EDR file-deletion telemetry with file hash, and process-attributed network telemetry with file hash, sharing a stable process entity
-- false_positives: Self-updating software and installers that replace or remove their own binary after execution
-- references: reports/sliver/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'sliver_self_delete_after_egress' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION', 'FILE_DELETION') OR event_type IN ('NETWORK_CONNECTION', 'FILE_DELETION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
