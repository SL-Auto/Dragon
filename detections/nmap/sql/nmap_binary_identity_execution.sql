-- source_yaral: detections/nmap/yaral/nmap_binary_identity_execution.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: nmap_binary_identity_execution
-- severity: medium
-- procedure_ids: NM-P01,NM-P02,NM-P03,NM-P05,NM-P06,NM-P07,NM-P08
-- description: Detects execution of the Nmap binary identified by its PE OriginalFileName (nmap.exe), which survives renaming on Windows, or by an image named nmap on other platforms. It covers default invocations such as nmap <target> that carry no option grammar.
-- log_source_prerequisites: PROCESS_LAUNCH telemetry with image path and PE OriginalFileName (Sysmon Event ID 1 OriginalFileName mapped to target.process.file.pe_file.original_file_name, or EDR equivalent).
-- false_positives: Authorized administrators and vulnerability-management hosts running Nmap; approve by host.
-- references: reports/nmap/source-analysis.md#procedure-analysis; public-rules/comparisons/nmap/nmap_cli_option_grammar.md; reviews/nmap/detection-review.md#nm-dr-08
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, hostname, process_path, command_line, original_file_name); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by hostname, process_path and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, hostname, process_path, command_line, original_file_name.
SELECT hostname, process_path, COUNT(*) AS matched_count, 'nmap_binary_identity_execution' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND event_type = 'PROCESS_LAUNCH'
  AND ((REGEXP_LIKE(original_file_name, '^nmap\.exe$', 'i')) OR (REGEXP_LIKE(process_path, '(\\nmap\.exe|/nmap)$', 'i')))
GROUP BY hostname, process_path
HAVING COUNT(*) >= 1;
