-- source_yaral: detections/chisel/yaral/chisel_udp_bind_with_tunnel_egress.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: chisel_udp_bind_with_tunnel_egress
-- severity: high
-- procedure_ids: CH-P03,CH-P04
-- description: Detects process-owned UDP bind or receive activity combined with outbound tunnel-like connectivity
-- log_source_prerequisites: EDR UDP bind or receive and outbound connection telemetry with stable process entity
-- false_positives: DNS relays media services VPNs and approved UDP proxies
-- references: reports/chisel/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'chisel_udp_bind_with_tunnel_egress' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION', 'UDP_BIND', 'UDP_RECEIVE') OR event_type IN ('NETWORK_CONNECTION', 'UDP_BIND', 'UDP_RECEIVE')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
