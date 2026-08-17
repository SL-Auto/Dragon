-- source_yaral: detections/havoc/yaral/havoc_recurrent_process_egress.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: havoc_recurrent_process_egress
-- severity: medium
-- procedure_ids: HV-P01,HV-P03
-- description: A process produces recurrent outbound network activity consistent with a long-lived task channel
-- log_source_prerequisites: Process-attributed network telemetry with stable process entity and event timestamps
-- false_positives: Monitoring, update, VPN, messaging and management agents
-- references: reports/havoc/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'havoc_recurrent_process_egress' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION') OR event_type IN ('NETWORK_CONNECTION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
