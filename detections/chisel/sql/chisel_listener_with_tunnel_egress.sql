-- source_yaral: detections/chisel/yaral/chisel_listener_with_tunnel_egress.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: chisel_listener_with_tunnel_egress
-- severity: high
-- procedure_ids: CH-P02,CH-P04,CH-P08
-- description: Detects one process listening locally while maintaining outbound connectivity consistent with bidirectional forwarding
-- log_source_prerequisites: EDR socket listen and outbound connect telemetry with stable process entity
-- false_positives: Approved proxies VPNs developer tunnels service meshes and remote support
-- references: reports/chisel/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'chisel_listener_with_tunnel_egress' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION', 'NETWORK_LISTEN') OR event_type IN ('NETWORK_CONNECTION', 'NETWORK_LISTEN')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
