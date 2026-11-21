-- source_yaral: detections/ligolo-ng/yaral/ligolo_agent_ping_probe_children.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: ligolo_agent_ping_probe_children
-- severity: high
-- procedure_ids: LG-P06
-- description: Detects a non-shell parent process spawning the system ping command with Ligolo-ng's exact single-probe argument shape (Windows: ping /n 1 /w 3000 <target>; other platforms: ping -c 1 -W 3 <target>) against three or more targets. This is the unprivileged fallback of the agent's ICMP host-discovery handler.
-- log_source_prerequisites: PROCESS_LAUNCH telemetry (Sysmon Event ID 1, Security 4688 with command line, or EDR, or Linux process execution) with the child command line, the parent image path, host and parent process ID.
-- false_positives: Monitoring agents or custom services that shell out to ping with the same single-probe arguments; approve their parent images after validation.
-- references: reports/ligolo-ng/source-analysis.md#procedure-analysis; reviews/ligolo-ng/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, hostname, parent_process_id, parent_process_path, command_line); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by hostname, parent_process_id and threshold. Hop window approximated by scheduling every 5 minutes over the trailing 10 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, hostname, parent_process_id, parent_process_path, command_line.
SELECT hostname, parent_process_id, COUNT(DISTINCT command_line) AS matched_count, 'ligolo_agent_ping_probe_children' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE
  AND event_type = 'PROCESS_LAUNCH'
  AND REGEXP_LIKE(command_line, '^"?([a-z]:\\[^"]*\\)?ping(\.exe)?"?\s+/n\s+1\s+/w\s+3000\s+\S+\s*$|^(\S*/)?ping\s+-c\s+1\s+-W\s+3\s+\S+\s*$', 'i')
  AND NOT REGEXP_LIKE(COALESCE(parent_process_path, ''), '(\\(cmd|powershell|pwsh|wscript|cscript)\.exe|/(ba|z|da|k|c|tc|fi)?sh)$', 'i')
GROUP BY hostname, parent_process_id
HAVING COUNT(DISTINCT command_line) >= 3;
