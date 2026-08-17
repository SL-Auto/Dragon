-- source_yaral: detections/impacket/yaral/impacket_terminal_services_control.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: impacket_terminal_services_control
-- severity: medium
-- procedure_ids: IMP-18
-- description: Detects unusual Terminal Services session connect, disconnect or logoff activity.
-- log_source_prerequisites: Terminal Services Operational and Security session events with actor and session.
-- false_positives: Helpdesk and session administration.
-- references: reports/impacket/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'impacket_terminal_services_control' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('23', '24', '25', '4778', '4779') OR event_type IN ('23', '24', '25', '4778', '4779')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
