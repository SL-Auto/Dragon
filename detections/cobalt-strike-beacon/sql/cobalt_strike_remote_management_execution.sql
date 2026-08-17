-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_remote_management_execution.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: cobalt_strike_remote_management_execution
-- severity: medium
-- procedure_ids: CSB-031,CSB-032,CSB-033
-- description: Detects WinRM, WMI or SSH remote-management session activity followed by a child process on the target.
-- log_source_prerequisites: Normalize WinRM Operational, WMI-Activity 5857-5861, SSH_AUTH/session and EDR PROCESS_LAUNCH with account, source, target/session and child process.
-- false_positives: Configuration management, helpdesk, orchestration, monitoring and approved remote administration.
-- references: reports/cobalt-strike-beacon/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'cobalt_strike_remote_management_execution' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('PROCESS_LAUNCH', 'SSH_AUTH', 'WINRM_SESSION', 'WMI_REMOTE_OPERATION') OR event_type IN ('PROCESS_LAUNCH', 'SSH_AUTH', 'WINRM_SESSION', 'WMI_REMOTE_OPERATION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
