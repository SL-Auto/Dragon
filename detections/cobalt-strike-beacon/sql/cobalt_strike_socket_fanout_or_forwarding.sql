-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_socket_fanout_or_forwarding.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: cobalt_strike_socket_fanout_or_forwarding
-- severity: medium
-- procedure_ids: CSB-009
-- description: Detects a single uncommon process connecting to many distinct destinations as a SOCKS/forwarding/pivot hypothesis.
-- log_source_prerequisites: Normalize process-attributed outbound NETWORK_CONNECTION with stable process entity and distinct target IP/port values plus signer/prevalence.
-- false_positives: Browsers, scanners, proxies, EDR, backup, software distribution and orchestration agents.
-- references: reports/cobalt-strike-beacon/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'cobalt_strike_socket_fanout_or_forwarding' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION') OR event_type IN ('NETWORK_CONNECTION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
