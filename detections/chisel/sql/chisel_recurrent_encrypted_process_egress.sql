-- source_yaral: detections/chisel/yaral/chisel_recurrent_encrypted_process_egress.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: chisel_recurrent_encrypted_process_egress
-- severity: medium
-- procedure_ids: CH-P01,CH-P10
-- description: Detects recurrent encrypted egress by one process to a stable destination consistent with maintained tunnelling
-- log_source_prerequisites: EDR network connections with stable process identity plus TLS or HTTP metadata
-- false_positives: Approved VPNs proxies remote support agents and application reconnect loops
-- references: reports/chisel/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'chisel_recurrent_encrypted_process_egress' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION') OR event_type IN ('NETWORK_CONNECTION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
