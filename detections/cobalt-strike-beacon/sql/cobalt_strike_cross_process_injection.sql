-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_cross_process_injection.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: cobalt_strike_cross_process_injection
-- severity: high
-- procedure_ids: CSB-018,CSB-019
-- description: Detects cross-process access followed by remote thread or executable-memory activity in the same target process.
-- log_source_prerequisites: Normalize Sysmon 8/10 or EDR PROCESS_OPEN, REMOTE_THREAD and EXECUTABLE_MEMORY with stable source and target process entities.
-- false_positives: EDR, debuggers, accessibility tools, application instrumentation and authorized diagnostics.
-- references: reports/cobalt-strike-beacon/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'cobalt_strike_cross_process_injection' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('EXECUTABLE_MEMORY', 'PROCESS_OPEN', 'REMOTE_THREAD') OR event_type IN ('EXECUTABLE_MEMORY', 'PROCESS_OPEN', 'REMOTE_THREAD')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
