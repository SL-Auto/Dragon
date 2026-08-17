-- source_yaral: detections/mimikatz/yaral/mimikatz_process_file_context.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: mimikatz_process_file_context
-- severity: low
-- procedure_ids: P01,P31,P33
-- description: Provides low-specificity process and output-file context for utility and staging procedures.
-- log_source_prerequisites: Process creation and EDR file create telemetry with ancestry, signer and path.
-- false_positives: Common administrative and user activity.
-- references: reports/mimikatz/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'mimikatz_process_file_context' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('FILE_CREATION', 'PROCESS_LAUNCH') OR event_type IN ('FILE_CREATION', 'PROCESS_LAUNCH')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
