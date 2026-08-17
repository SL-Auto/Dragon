-- source_yaral: detections/sliver/yaral/sliver_relay_to_novel_destination.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: sliver_relay_to_novel_destination
-- severity: high
-- procedure_ids: PROC-005,PROC-021
-- description: A process that accepted an inbound connection also makes an outbound connection to a distinct destination in the same window
-- log_source_prerequisites: EDR/firewall inbound-accept and outbound-connect telemetry sharing a stable process entity, with source and destination IP
-- false_positives: Legitimate reverse proxies, load balancers, VPN concentrators, and remote-support/relay software
-- references: reports/sliver/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'sliver_relay_to_novel_destination' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION') OR event_type IN ('NETWORK_CONNECTION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
