-- source_yaral: detections/nmap/yaral/ncat_exec_or_broker_grammar.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: ncat_exec_or_broker_grammar
-- severity: high
-- procedure_ids: NM-P15
-- description: Detects a process started with Ncat command-execution or relay grammar regardless of the executable name: --sh-exec, --lua-exec, --broker, --chat or --keep-open; or -e/--exec/-c combined with listen mode (-l with only n, v, k or p companions) and a port argument (NM-DR-05).
-- log_source_prerequisites: PROCESS_LAUNCH telemetry (Sysmon Event ID 1, Security 4688 with command line, Linux auditd EXECVE or EDR) with the full command line, image path and host.
-- false_positives: Administrators using Ncat for authorized troubleshooting.
-- references: reports/nmap/source-analysis.md#procedure-analysis; reviews/nmap/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, hostname, process_path, command_line); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by hostname, process_path and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, hostname, process_path, command_line.
SELECT hostname, process_path, COUNT(*) AS matched_count, 'ncat_exec_or_broker_grammar' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND event_type = 'PROCESS_LAUNCH'
  AND ((REGEXP_LIKE(command_line, '(^|\s)--(sh-exec|lua-exec|broker|chat|keep-open)(\s|=|$)', 'i')) OR (REGEXP_LIKE(command_line, '(^|\s)(-e|--exec|-c)(\s|=)\S+', 'i') AND REGEXP_LIKE(command_line, '(^|\s)(-[nvk]*l[nvkp]*|--listen)(\s|$)', 'i') AND REGEXP_LIKE(command_line, '\s\d{2,5}(\s|$)', 'i')))
GROUP BY hostname, process_path
HAVING COUNT(*) >= 1;
