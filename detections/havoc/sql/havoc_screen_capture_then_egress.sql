-- source_yaral: detections/havoc/yaral/havoc_screen_capture_then_egress.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: havoc_screen_capture_then_egress
-- severity: high
-- procedure_ids: HV-P14
-- description: A process with screen-capture telemetry also performs outbound network activity
-- log_source_prerequisites: Tenant-verified EDR screen capture semantic event and process-attributed network telemetry
-- false_positives: Conferencing, support, accessibility and approved screen-recording software
-- references: reports/havoc/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'havoc_screen_capture_then_egress' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION', 'SCREEN_CAPTURE') OR event_type IN ('NETWORK_CONNECTION', 'SCREEN_CAPTURE')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
