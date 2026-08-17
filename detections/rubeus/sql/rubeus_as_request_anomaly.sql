-- source_yaral: detections/rubeus/yaral/rubeus_as_request_anomaly.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: rubeus_as_request_anomaly
-- severity: high
-- procedure_ids: PROC-001
-- description: Detects one source making AS requests for multiple principals or atypical preauthentication patterns.
-- log_source_prerequisites: Normalize DC Security 4768 with source IP, target account, preauthentication type, result, and encryption type.
-- false_positives: Identity monitoring, password audits, migration, and authorized assessment.
-- references: RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'rubeus_as_request_anomaly' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4768') OR event_type IN ('4768')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
