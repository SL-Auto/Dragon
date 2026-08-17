-- source_yaral: detections/sliver/yaral/sliver_low_and_slow_udp_beacon.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: sliver_low_and_slow_udp_beacon
-- severity: medium
-- procedure_ids: PROC-004
-- description: One process makes low-volume, time-spread, repeated DNS or UDP connections to the same destination and port
-- log_source_prerequisites: Process-attributed DNS or UDP network telemetry with stable destination and port
-- false_positives: DNS resolvers, VPN/WireGuard clients, monitoring agents, chat/voice UDP applications
-- references: reports/sliver/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'sliver_low_and_slow_udp_beacon' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_DNS', 'NETWORK_CONNECTION') OR event_type IN ('NETWORK_DNS', 'NETWORK_CONNECTION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
