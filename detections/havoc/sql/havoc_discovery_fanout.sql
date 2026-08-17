-- source_yaral: detections/havoc/yaral/havoc_discovery_fanout.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: havoc_discovery_fanout
-- severity: medium
-- procedure_ids: HV-P04,HV-P13
-- description: One process performs rapid directory SMB or RPC discovery across multiple targets
-- log_source_prerequisites: Process-attributed LDAP SMB RPC or discovery events with target identity
-- false_positives: Asset inventory, vulnerability scanners, identity governance and administrative scripts
-- references: reports/havoc/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'havoc_discovery_fanout' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('PROCESS_DISCOVERY', 'RPC_CALL', 'SMB_SESSION') OR event_type IN ('PROCESS_DISCOVERY', 'RPC_CALL', 'SMB_SESSION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
