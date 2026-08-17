-- source_yaral: detections/impacket/yaral/impacket_sensitive_file_or_replication_access.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: impacket_sensitive_file_or_replication_access
-- severity: critical
-- procedure_ids: IMP-13
-- description: Detects directory replication access or sensitive remote credential-store reads.
-- log_source_prerequisites: DC 4662 and SMB/object events with access GUID, actor, source and path.
-- false_positives: Domain controllers, approved replication, backup and recovery.
-- references: reports/impacket/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'impacket_sensitive_file_or_replication_access' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4662', '4663', '5145') OR event_type IN ('4662', '4663', '5145')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
