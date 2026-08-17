-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_discovery_fanout.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: cobalt_strike_discovery_fanout
-- severity: medium
-- procedure_ids: CSB-021
-- description: Detects port/network discovery fan-out from one process without relying on Beacon command names.
-- log_source_prerequisites: Normalize process-attributed NETWORK_CONNECTION attempts including failures with destination IP/port and stable process entity.
-- false_positives: Vulnerability scanners, monitoring, software distribution, service discovery and network management.
-- references: reports/cobalt-strike-beacon/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'cobalt_strike_discovery_fanout' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION') OR event_type IN ('NETWORK_CONNECTION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
