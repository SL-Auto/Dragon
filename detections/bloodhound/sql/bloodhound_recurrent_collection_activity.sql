-- source_yaral: detections/bloodhound/yaral/bloodhound_recurrent_collection_activity.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: bloodhound_recurrent_collection_activity
-- severity: medium
-- procedure_ids: BH-014
-- description: Detects repeated directory or remote-host collection bursts from the same process entity.
-- log_source_prerequisites: Stable process entity and normalized LDAP_SEARCH, RPC_CALL or REGISTRY_READ events retained for several hours.
-- false_positives: Scheduled identity inventory, monitoring and compliance collection.
-- references: reports/bloodhound/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'bloodhound_recurrent_collection_activity' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('LDAP_SEARCH', 'REGISTRY_READ', 'RPC_CALL') OR event_type IN ('LDAP_SEARCH', 'REGISTRY_READ', 'RPC_CALL')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
