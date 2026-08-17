-- source_yaral: detections/mimikatz/yaral/mimikatz_token_process_control.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: mimikatz_token_process_control
-- severity: medium
-- procedure_ids: P02,P03,P04,P05
-- description: Detects endpoint-reported token manipulation, parent override or sensitive process control.
-- log_source_prerequisites: EDR token and process-control telemetry with source, target, user and operation.
-- false_positives: Security, support, accessibility and process-broker software.
-- references: reports/mimikatz/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'mimikatz_token_process_control' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('*') OR event_type IN ('*')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
