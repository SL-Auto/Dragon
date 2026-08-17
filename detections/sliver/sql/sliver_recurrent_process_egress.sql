-- source_yaral: detections/sliver/yaral/sliver_recurrent_process_egress.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: sliver_recurrent_process_egress
-- severity: medium
-- procedure_ids: PROC-002,PROC-003
-- description: One process entity repeatedly communicates outbound to the same destination, spread across multiple minutes
-- log_source_prerequisites: Process-attributed network events with stable process entity and destination
-- false_positives: Agents, updaters, browsers, monitoring
-- references: reports/sliver/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'sliver_recurrent_process_egress' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION') OR event_type IN ('NETWORK_CONNECTION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
