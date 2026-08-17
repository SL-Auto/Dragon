-- source_yaral: detections/impacket/yaral/impacket_short_lived_command_service.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: impacket_short_lived_command_service
-- severity: high
-- procedure_ids: IMP-03
-- description: Detects service installation paths that invoke a command shell with output redirection.
-- log_source_prerequisites: Normalize Windows 7045 or 4697 service-install events and preserve the full service image path.
-- false_positives: Scripted break-glass administration and management products that wrap commands in temporary services.
-- references: reports/impacket/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'impacket_short_lived_command_service' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4697', '7045') OR event_type IN ('4697', '7045')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
