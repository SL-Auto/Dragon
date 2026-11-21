-- source_yaral: detections/ligolo-ng/yaral/ligolo_agent_command_line_trust_flags.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: ligolo_agent_command_line_trust_flags
-- severity: high
-- procedure_ids: LG-P01,LG-P09
-- description: Detects a process started with the agent's compiled flag grammar: a -connect target together with -ignore-cert or -accept-fingerprint followed by a 64-hex-character SHA-256 value. Flag names are fixed in the agent binary and survive renaming the executable.
-- log_source_prerequisites: PROCESS_LAUNCH telemetry (Sysmon Event ID 1, Security 4688 with command line, Linux auditd EXECVE or EDR) with the full command line, image path and host.
-- false_positives: Other tools that happen to share both -connect and -ignore-cert or -accept-fingerprint flags; authorized red-team exercises.
-- references: reports/ligolo-ng/source-analysis.md#evidence; public-rules/comparisons/ligolo-ng/ligolo_agent_listener_with_tunnel_egress.md; reviews/ligolo-ng/detection-review.md#lg-dr-11
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, hostname, process_path, command_line); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by hostname, process_path and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, hostname, process_path, command_line.
SELECT hostname, process_path, COUNT(*) AS matched_count, 'ligolo_agent_command_line_trust_flags' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND event_type = 'PROCESS_LAUNCH'
  AND REGEXP_LIKE(command_line, '(^|\s)-{1,2}connect(\s+|=)"?\S+', 'i')
  AND REGEXP_LIKE(command_line, '(^|\s)-{1,2}(ignore-cert(\s|=|$)|accept-fingerprint(\s+|=)"?[0-9a-f]{64})', 'i')
GROUP BY hostname, process_path
HAVING COUNT(*) >= 1;
