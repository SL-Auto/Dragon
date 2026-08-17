-- source_yaral: detections/mimikatz/yaral/mimikatz_directory_mutation.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: mimikatz_directory_mutation
-- severity: high
-- procedure_ids: P15,P29
-- description: Detects directory replication, SIDHistory or identity-attribute mutation requiring source-host triage.
-- log_source_prerequisites: Domain controller 4662 and 5136 events normalized with subject, object, attribute and source.
-- false_positives: Approved domain promotion, identity migration and directory administration.
-- references: reports/mimikatz/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'mimikatz_directory_mutation' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4662', '5136') OR event_type IN ('4662', '5136')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
