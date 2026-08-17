-- source_yaral: detections/sliver/yaral/sliver_dns_or_udp_process_egress.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: sliver_dns_or_udp_process_egress
-- severity: medium
-- procedure_ids: PROC-004
-- description: High-volume DNS or UDP from one process
-- log_source_prerequisites: Process-attributed DNS or UDP network telemetry
-- false_positives: Resolvers, browsers, VPN clients
-- references: reports/sliver/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'sliver_dns_or_udp_process_egress' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_DNS') OR event_type IN ('NETWORK_DNS')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
