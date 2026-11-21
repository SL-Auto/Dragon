-- source_yaral: detections/nmap/yaral/nmap_cli_option_grammar.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: nmap_cli_option_grammar
-- severity: high
-- procedure_ids: NM-P01,NM-P02,NM-P03,NM-P04,NM-P05,NM-P06,NM-P07,NM-P08,NM-P09,NM-P10,NM-P11,NM-P12,NM-P13,NM-P16
-- description: Detects a process started with Nmap or Nping option grammar regardless of the executable name: an Nmap scan-type flag (-sS, -sT, -sU, -sV, -sC and similar) together with a port, discovery, script, output or timing option; or Nping's distinctive long options.
-- log_source_prerequisites: PROCESS_LAUNCH telemetry (Sysmon Event ID 1, Security 4688 with command line, Linux auditd EXECVE or EDR) with the full command line, image path and host.
-- false_positives: Authorized network administrators, vulnerability-management scanners and IT asset discovery running Nmap; approve by host and account.
-- references: reports/nmap/source-analysis.md#procedure-analysis; reviews/nmap/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, hostname, process_path, command_line); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by hostname, process_path and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, hostname, process_path, command_line.
SELECT hostname, process_path, COUNT(*) AS matched_count, 'nmap_cli_option_grammar' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND event_type = 'PROCESS_LAUNCH'
  AND ((REGEXP_LIKE(command_line, '(^|\s)-s[STUVACNFXWMOYZIL]{1,2}(\s|$)', 'i') AND REGEXP_LIKE(command_line, '(^|\s)(-p\s*[0-9TU:,-]+|-p-|-Pn|-P[SAUYEPM][0-9,]*|-O(\s|$)|-A(\s|$)|-T[0-5](\s|$)|--top-ports|--script(\s|=)|-o[ANXGS](\s|$)|--min-rate|--max-retries|--open(\s|$))', 'i')) OR (REGEXP_LIKE(command_line, '(^|\s)--(script|script-args)(\s|=)\S*(vuln|exploit|brute|auth|intrusive|dos|broadcast|discovery|default|safe|[a-z0-9-]+\.nse)', 'i')) OR (REGEXP_LIKE(command_line, '(^|\s)--(echo-server|echo-client|icmp-type|tcp-connect|arp-type)(\s|=)', 'i')))
GROUP BY hostname, process_path
HAVING COUNT(*) >= 1;
