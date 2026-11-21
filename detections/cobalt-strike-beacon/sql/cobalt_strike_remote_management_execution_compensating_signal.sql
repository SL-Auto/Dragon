-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_remote_management_execution_compensating_signal.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cobalt_strike_remote_management_execution_compensating_signal
-- severity: medium
-- procedure_ids: CSB-031,CSB-032,CSB-033
-- description: Correlates a WinRM, remote WMI or SSH session on a target with a subsequent process launched by the matching remote-management host process (wsmprovhost.exe, wmiprvse.exe or sshd) as the same account. This replaces the base rule's any-process-by-the-same-user join with process lineage that ties the child to the remote-management channel.
-- log_source_prerequisites: Target-side WINRM_SESSION, WMI_REMOTE_OPERATION or SSH_AUTH events with target host and account, plus PROCESS_LAUNCH on the same host where principal.process is the launching (parent) process, joined on host and account within 10 minutes, session first.
-- false_positives: Remote administration, configuration management (DSC, Ansible over WinRM/SSH), monitoring and patching that run commands through WinRM, WMI or SSH.
-- references: reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_remote_management_execution.md; reviews/cobalt-strike-beacon/detection-review.md#dr-23
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, hostname, user_id, process_path, source_ip); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native ordered two-event correlation on hostname, user_id within 10 minutes (first event before second). Exact per-pair self-join; regex, REGEXP_SUBSTR and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, hostname, user_id, process_path, source_ip.
WITH first_leg AS (
  SELECT * FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '20' MINUTE
    AND event_type IN ('WINRM_SESSION', 'WMI_REMOTE_OPERATION', 'SSH_AUTH')
 ),
second_leg AS (
  SELECT * FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '20' MINUTE
    AND event_type = 'PROCESS_LAUNCH'
    AND REGEXP_LIKE(process_path, '(\\(wsmprovhost|wmiprvse|sshd)\.exe|/sshd)$', 'i')
)
SELECT a.hostname, a.user_id, MIN(a.event_time) AS first_time, MAX(b.event_time) AS last_time, 'cobalt_strike_remote_management_execution_compensating_signal' AS canonical_rule
FROM first_leg a
JOIN second_leg b
  ON a.hostname = b.hostname
 AND a.user_id = b.user_id
 AND b.event_time BETWEEN a.event_time AND a.event_time + INTERVAL '10' MINUTE
GROUP BY a.hostname, a.user_id;
