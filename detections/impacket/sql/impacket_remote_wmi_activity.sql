-- source_yaral: detections/impacket/yaral/impacket_remote_wmi_activity.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: impacket_remote_wmi_activity
-- severity: high
-- procedure_ids: IMP-05
-- description: Detects a command interpreter created by the WMI provider; SMB output activity is optional enrichment rather than a required event.
-- log_source_prerequisites: Normalize WMI Activity or EDR process creation with host, account, parent process, child process, and command line.
-- false_positives: Endpoint management, inventory, remediation, and authorized WMI administration.
-- references: reports/impacket/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'impacket_remote_wmi_activity' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('PROCESS_LAUNCH') OR event_type IN ('PROCESS_LAUNCH')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
