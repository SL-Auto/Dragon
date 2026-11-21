-- source_yaral: detections/scoutsuite/yaral/scoutsuite_cli_execution.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: scoutsuite_cli_execution
-- severity: medium
-- procedure_ids: SS-P06
-- description: Detects a process launched with ScoutSuite's command grammar on a monitored host: scout followed by a provider subcommand (aws, azure, gcp, aliyun, oci, do, kubernetes), or scout.py or the ScoutSuite module.
-- log_source_prerequisites: PROCESS_LAUNCH telemetry with the full command line, image path and host.
-- false_positives: Authorized cloud security assessments.
-- references: reports/scoutsuite/source-analysis.md#procedure-analysis; reviews/scoutsuite/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, hostname, process_path, command_line); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by hostname, process_path and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, hostname, process_path, command_line.
SELECT hostname, process_path, COUNT(*) AS matched_count, 'scoutsuite_cli_execution' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND event_type = 'PROCESS_LAUNCH'
  AND REGEXP_LIKE(command_line, '((^|[\s\\/\"])scout(\.exe|\.py)?\"?\s+(aws|azure|gcp|aliyun|oci|do|kubernetes)(\s|$)|-m\s+ScoutSuite(\s|$))', 'i')
GROUP BY hostname, process_path
HAVING COUNT(*) >= 1;
