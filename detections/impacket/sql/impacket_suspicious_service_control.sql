-- source_yaral: detections/impacket/yaral/impacket_suspicious_service_control.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: impacket_suspicious_service_control
-- severity: high
-- procedure_ids: IMP-03
-- description: Detects service creation or configuration following a remote logon.
-- log_source_prerequisites: Windows 4624 and 4697/7045 with host, account and source.
-- false_positives: Software deployment and remote support.
-- references: reports/impacket/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'impacket_suspicious_service_control' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4624', '4697', '7045') OR event_type IN ('4624', '4697', '7045')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
