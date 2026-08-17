-- source_yaral: detections/bloodhound/yaral/bloodhound_service_protocol_probe_fanout.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: bloodhound_service_protocol_probe_fanout
-- severity: medium
-- procedure_ids: BH-013
-- description: Detects one process probing WebDAV, SMB, LDAP and LDAPS capability across many hosts.
-- log_source_prerequisites: Process-attributed network events with target host, port, protocol and connection result.
-- false_positives: Vulnerability scanners, service inventory and network monitoring.
-- references: reports/bloodhound/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'bloodhound_service_protocol_probe_fanout' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION') OR event_type IN ('NETWORK_CONNECTION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
