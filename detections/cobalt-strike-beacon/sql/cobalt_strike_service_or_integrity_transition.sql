-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_service_or_integrity_transition.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: cobalt_strike_service_or_integrity_transition
-- severity: high
-- procedure_ids: CSB-020
-- description: Detects a new service or unusual medium-to-high/SYSTEM integrity transition correlated to process execution.
-- log_source_prerequisites: Normalize Windows 4697/System 7045 and EDR INTEGRITY_TRANSITION with subject, service, image, source/child process, old/new integrity and host.
-- false_positives: Software deployment, driver installation, endpoint management and approved elevation tools.
-- references: reports/cobalt-strike-beacon/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'cobalt_strike_service_or_integrity_transition' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4697', '7045', 'INTEGRITY_TRANSITION') OR event_type IN ('4697', '7045', 'INTEGRITY_TRANSITION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
