-- source_yaral: detections/chisel/yaral/chisel_stdio_network_bridge.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: chisel_stdio_network_bridge
-- severity: medium
-- procedure_ids: CH-P06
-- description: Detects a process with redirected standard handles that also establishes sustained outbound connectivity
-- log_source_prerequisites: EDR process handle or redirected stdio semantic telemetry and outbound network connections
-- false_positives: Remote administration automation IDE terminals and container entrypoints
-- references: reports/chisel/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'chisel_stdio_network_bridge' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION', 'PROCESS_STDIO_REDIRECT') OR event_type IN ('NETWORK_CONNECTION', 'PROCESS_STDIO_REDIRECT')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
