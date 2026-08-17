-- source_yaral: detections/havoc/yaral/havoc_memory_execution_from_network_process.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: havoc_memory_execution_from_network_process
-- severity: high
-- procedure_ids: HV-P09,HV-P10,HV-P11
-- description: A network-active process performs cross-process access, injection or memory-backed execution
-- log_source_prerequisites: Tenant-verified EDR process access injection memory execution or CLR load events plus process network telemetry
-- false_positives: EDR, debuggers, profilers, accessibility and managed-runtime hosts
-- references: reports/havoc/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'havoc_memory_execution_from_network_process' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('CLR_ASSEMBLY_LOAD', 'MEMORY_EXECUTION', 'NETWORK_CONNECTION', 'PROCESS_INJECTION', 'REMOTE_THREAD') OR event_type IN ('CLR_ASSEMBLY_LOAD', 'MEMORY_EXECUTION', 'NETWORK_CONNECTION', 'PROCESS_INJECTION', 'REMOTE_THREAD')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
