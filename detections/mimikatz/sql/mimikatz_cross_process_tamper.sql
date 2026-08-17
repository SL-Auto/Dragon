-- source_yaral: detections/mimikatz/yaral/mimikatz_cross_process_tamper.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: mimikatz_cross_process_tamper
-- severity: high
-- procedure_ids: P22,P27,P28,P32,P40
-- description: Detects endpoint-reported cross-process memory tampering affecting security-sensitive processes.
-- log_source_prerequisites: EDR process tamper telemetry normalized with source and target processes and operation.
-- false_positives: Approved security sensors, diagnostics, accessibility and support tooling.
-- references: reports/mimikatz/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'mimikatz_cross_process_tamper' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('PROCESS_OPEN') OR event_type IN ('PROCESS_OPEN')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
