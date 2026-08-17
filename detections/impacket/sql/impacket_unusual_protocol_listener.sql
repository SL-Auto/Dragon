-- source_yaral: detections/impacket/yaral/impacket_unusual_protocol_listener.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: impacket_unusual_protocol_listener
-- severity: medium
-- procedure_ids: IMP-02
-- description: Detects non-server processes listening on SMB or relay-associated service ports.
-- log_source_prerequisites: EDR network-listen events with process, host, port and direction.
-- false_positives: Approved file servers, development services and security tools.
-- references: reports/impacket/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'impacket_unusual_protocol_listener' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION') OR event_type IN ('NETWORK_CONNECTION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
