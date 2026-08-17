-- source_yaral: detections/impacket/yaral/impacket_smb_sensitive_file_activity.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: impacket_smb_sensitive_file_activity
-- severity: high
-- procedure_ids: IMP-01,IMP-13
-- description: Detects remote SMB access to credential-bearing or administrative paths.
-- log_source_prerequisites: Windows 5145/4663 or EDR SMB file events with source, account, share, path and access.
-- false_positives: Backup, migration, domain administration and security scanning.
-- references: reports/impacket/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'impacket_smb_sensitive_file_activity' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4663', '5145') OR event_type IN ('4663', '5145')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
