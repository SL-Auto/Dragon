-- source_yaral: detections/nmap/yaral/nmap_output_file_artifacts.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: nmap_output_file_artifacts
-- severity: medium
-- procedure_ids: NM-P13
-- description: Detects creation of a grepable Nmap output file (.gnmap), produced by -oG or alongside .nmap and .xml by -oA.
-- log_source_prerequisites: FILE_CREATION telemetry (Sysmon Event ID 11 or EDR) with target path, host and creating process.
-- false_positives: Administrators saving authorized scan results.
-- references: reports/nmap/source-analysis.md#procedure-analysis; reviews/nmap/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, hostname, target_path, process_path); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by hostname and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, hostname, target_path, process_path.
SELECT hostname, COUNT(*) AS matched_count, 'nmap_output_file_artifacts' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND event_type = 'FILE_CREATION'
  AND REGEXP_LIKE(target_path, '\.gnmap$', 'i')
GROUP BY hostname
HAVING COUNT(*) >= 1;
