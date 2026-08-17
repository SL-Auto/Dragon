-- source_yaral: detections/impacket/yaral/impacket_remote_service_binary_sequence.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: impacket_remote_service_binary_sequence
-- severity: high
-- procedure_ids: IMP-03
-- description: Correlates an administrative-share file write with remote service installation on the same host.
-- log_source_prerequisites: Normalize Windows 5145 plus 7045/4697 or EDR file/service events with target host, account, source IP, service path, and timestamps.
-- false_positives: Software deployment, endpoint management, backup, and approved remote support.
-- references: reports/impacket/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'impacket_remote_service_binary_sequence' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4697', '5145', '7045') OR event_type IN ('4697', '5145', '7045')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
