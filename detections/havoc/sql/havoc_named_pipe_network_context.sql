-- source_yaral: detections/havoc/yaral/havoc_named_pipe_network_context.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: havoc_named_pipe_network_context
-- severity: high
-- procedure_ids: HV-P02,HV-P15
-- description: A network-active process creates or connects to a named pipe
-- log_source_prerequisites: EDR or Sysmon named-pipe create/connect normalized with process network telemetry
-- false_positives: Remote administration, software deployment, backup and clustered applications
-- references: reports/havoc/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'havoc_named_pipe_network_context' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('17', '18', 'NAMED_PIPE_CONNECT', 'NAMED_PIPE_CREATE', 'NETWORK_CONNECTION') OR event_type IN ('17', '18', 'NAMED_PIPE_CONNECT', 'NAMED_PIPE_CREATE', 'NETWORK_CONNECTION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
