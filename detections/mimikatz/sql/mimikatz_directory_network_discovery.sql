-- source_yaral: detections/mimikatz/yaral/mimikatz_directory_network_discovery.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: mimikatz_directory_network_discovery
-- severity: low
-- procedure_ids: P30
-- description: Surfaces high-volume LDAP or RPC discovery reported by network or endpoint sensors.
-- log_source_prerequisites: LDAP, RPC or EDR discovery telemetry with process, account, destination and operation.
-- false_positives: Inventory, identity, monitoring and administration tools.
-- references: reports/mimikatz/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'mimikatz_directory_network_discovery' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('*') OR event_type IN ('*')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
