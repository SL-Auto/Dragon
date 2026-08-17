-- source_yaral: detections/rubeus/yaral/rubeus_asrep_roast_sequence.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: rubeus_asrep_roast_sequence
-- severity: high
-- procedure_ids: PROC-003
-- description: Detects one source requesting no-preauthentication AS responses for multiple accounts.
-- log_source_prerequisites: Normalize 4768 with source IP, account, and PreAuthType in the configured additional field.
-- false_positives: Authorized account configuration audits and identity assessment.
-- references: RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'rubeus_asrep_roast_sequence' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4768') OR event_type IN ('4768')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
