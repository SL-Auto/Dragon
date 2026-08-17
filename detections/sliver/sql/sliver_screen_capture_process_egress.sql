-- source_yaral: detections/sliver/yaral/sliver_screen_capture_process_egress.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: sliver_screen_capture_process_egress
-- severity: high
-- procedure_ids: PROC-014
-- description: Tenant-normalized screen capture followed by same-process egress
-- log_source_prerequisites: Verified EDR screen capture mapping and stable PID network telemetry
-- false_positives: Conferencing, remote support, screenshot tools
-- references: reports/sliver/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'sliver_screen_capture_process_egress' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION', 'USER_RESOURCE_ACCESS') OR event_type IN ('NETWORK_CONNECTION', 'USER_RESOURCE_ACCESS')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
