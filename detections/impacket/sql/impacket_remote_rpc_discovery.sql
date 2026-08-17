-- source_yaral: detections/impacket/yaral/impacket_remote_rpc_discovery.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: impacket_remote_rpc_discovery
-- severity: medium
-- procedure_ids: IMP-08,IMP-16
-- description: Detects unusual remote RPC interface enumeration and discovery volume.
-- log_source_prerequisites: RPC-aware network or ETW telemetry with source, target and interface UUID.
-- false_positives: Inventory, vulnerability scanning and management systems.
-- references: reports/impacket/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'impacket_remote_rpc_discovery' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION') OR event_type IN ('NETWORK_CONNECTION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
