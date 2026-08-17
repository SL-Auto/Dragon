-- source_yaral: detections/bloodhound/yaral/bloodhound_ldap_directory_discovery_fanout.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: bloodhound_ldap_directory_discovery_fanout
-- severity: high
-- procedure_ids: BH-002,BH-004
-- description: Detects broad process-attributed LDAP enumeration across multiple directory object categories.
-- log_source_prerequisites: Directory-side or EDR LDAP_SEARCH events with source process/account, base DN, filter, attributes and result category.
-- false_positives: Identity governance, directory inventory, migration and authorized security assessment.
-- references: reports/bloodhound/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'bloodhound_ldap_directory_discovery_fanout' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('1644', 'LDAP_SEARCH') OR event_type IN ('1644', 'LDAP_SEARCH')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
