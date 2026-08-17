-- source_yaral: detections/sliver/yaral/sliver_process_behavior_cluster.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: sliver_process_behavior_cluster
-- severity: medium
-- procedure_ids: PROC-001
-- description: New process followed by outbound activity
-- log_source_prerequisites: Process launch and process network UDM with stable PID
-- false_positives: New legitimate network software
-- references: reports/sliver/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'sliver_process_behavior_cluster' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION', 'PROCESS_LAUNCH') OR event_type IN ('NETWORK_CONNECTION', 'PROCESS_LAUNCH')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
