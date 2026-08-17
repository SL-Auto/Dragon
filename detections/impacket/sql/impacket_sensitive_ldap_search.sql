-- source_yaral: detections/impacket/yaral/impacket_sensitive_ldap_search.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: impacket_sensitive_ldap_search
-- severity: medium
-- procedure_ids: IMP-09
-- description: Detects LDAP searches for sensitive credential or delegation attributes.
-- log_source_prerequisites: LDAP diagnostic 1644 or directory audit preserving filter and requested attributes.
-- false_positives: Identity governance, AD health and security assessment.
-- references: reports/impacket/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'impacket_sensitive_ldap_search' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('1644') OR event_type IN ('1644')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
