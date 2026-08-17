-- source_yaral: detections/rubeus/yaral/rubeus_ticket_artifact_access_or_creation.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: rubeus_ticket_artifact_access_or_creation
-- severity: medium
-- procedure_ids: PROC-008,PROC-009,PROC-010,PROC-013
-- description: Detects an unapproved process accessing or creating a Kerberos ticket-cache artifact file by extension.
-- log_source_prerequisites: Normalize EDR file read/create events with process, user, path, extension, and signer, plus an approved-Kerberos-tool process enrichment.
-- false_positives: Incident response, Kerberos troubleshooting, development, labs, and approved assessments where the approved-tool enrichment is stale or incomplete.
-- references: RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_ticket_artifact_access_or_creation.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling. The weak free-text "asrep"/"kerberoast" substring branch was removed; only the .kirbi/.ccache-extension-plus-unapproved-process branch remains, so the approved-tool enrichment join is required, not optional.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'rubeus_ticket_artifact_access_or_creation' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('FILE_CREATION', 'FILE_READ') OR event_type IN ('FILE_CREATION', 'FILE_READ')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
