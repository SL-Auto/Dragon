-- source_yaral: detections/sliver/yaral/sliver_process_access_from_network_process.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: sliver_process_access_from_network_process
-- severity: high
-- procedure_ids: PROC-011,PROC-012,PROC-015
-- description: Outbound-network process performs sensitive process access, injection, dump, or memory load
-- log_source_prerequisites: Tenant-verified EDR process access/injection/memory event plus stable PID network telemetry
-- false_positives: EDR, debuggers, profilers, accessibility
-- references: reports/sliver/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'sliver_process_access_from_network_process' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION', 'PROCESS_MODULE_LOAD') OR event_type IN ('NETWORK_CONNECTION', 'PROCESS_MODULE_LOAD')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
