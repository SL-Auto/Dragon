-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_directory_discovery.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: cobalt_strike_directory_discovery
-- severity: medium
-- procedure_ids: CSB-022
-- description: Detects broad directory/RPC enumeration by one endpoint process across multiple object classes or operations.
-- log_source_prerequisites: Normalize LDAP_QUERY or RPC_CALL with client process/host/account and query object class/filter or interface operation.
-- false_positives: Identity governance, endpoint inventory, directory health, administration and vulnerability assessment.
-- references: reports/cobalt-strike-beacon/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'cobalt_strike_directory_discovery' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('LDAP_QUERY', 'LDAP_SEARCH', 'RPC_CALL') OR event_type IN ('LDAP_QUERY', 'LDAP_SEARCH', 'RPC_CALL')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
