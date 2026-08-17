-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_remote_service_sequence.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: cobalt_strike_remote_service_sequence
-- severity: high
-- procedure_ids: CSB-030
-- description: Correlates network share access with service installation on the target from the same account/source context.
-- log_source_prerequisites: Normalize target 5140/5145 and 4697/7045 with source IP/host, account/logon context, share/path, service/image and target host.
-- false_positives: Software distribution, endpoint management, backup agents and authorized remote service administration.
-- references: reports/cobalt-strike-beacon/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'cobalt_strike_remote_service_sequence' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4697', '5140', '5145', '7045') OR event_type IN ('4697', '5140', '5145', '7045')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
