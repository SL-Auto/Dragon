-- source_yaral: detections/bloodhound/yaral/bloodhound_sensitive_directory_attribute_reads.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: bloodhound_sensitive_directory_attribute_reads
-- severity: high
-- procedure_ids: BH-003,BH-005
-- description: Detects LDAP searches requesting security descriptors or AD CS relationship attributes.
-- log_source_prerequisites: LDAP query telemetry containing requested attributes or controls, source identity/process and naming context.
-- false_positives: Directory permissions auditing, PKI administration and identity governance.
-- references: reports/bloodhound/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'bloodhound_sensitive_directory_attribute_reads' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('1644', '4662', 'LDAP_SEARCH') OR event_type IN ('1644', '4662', 'LDAP_SEARCH')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
