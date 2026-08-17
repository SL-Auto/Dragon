-- source_yaral: detections/bloodhound/yaral/bloodhound_sysvol_policy_file_collection.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: bloodhound_sysvol_policy_file_collection
-- severity: medium
-- procedure_ids: BH-011
-- description: Detects one source reading multiple policy artifacts from SYSVOL.
-- log_source_prerequisites: Windows 5145 or EDR FILE_READ with source, account, share/path and target DC.
-- false_positives: Group Policy processing, configuration management, backup and policy auditing.
-- references: reports/bloodhound/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'bloodhound_sysvol_policy_file_collection' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('5145', 'FILE_READ') OR event_type IN ('5145', 'FILE_READ')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
