-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_powershell_or_clr_in_unusual_host_compensating_signal.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cobalt_strike_powershell_or_clr_in_unusual_host_compensating_signal
-- severity: high
-- procedure_ids: CSB-015,CSB-017
-- description: Detects CLR/CoreCLR module load either into a native Windows host binary that is not a .NET application (the sacrificial-process pattern used for in-memory assembly execution) or into a process that is both unsigned and rare, providing an alternate detection path when runtime-expected/CLR_RUNTIME_LOAD telemetry is unavailable.
-- log_source_prerequisites: Normalize MODULE_LOAD (Sysmon 7 or EDR image load) for clr.dll/coreclr.dll with loading process image path, signer and prevalence.
-- false_positives: Custom .NET hosts, IDEs, installers, and management agents that legitimately embed the CLR in an uncommon or unsigned process.
-- references: reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_powershell_or_clr_in_unusual_host.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, hostname, target_path, process_path, process_signed, process_prevalence); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, hostname, target_path, process_path, process_signed, process_prevalence.
SELECT *, 'cobalt_strike_powershell_or_clr_in_unusual_host_compensating_signal' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE
  AND event_type = 'MODULE_LOAD'
  AND REGEXP_LIKE(target_path, '\\(clr|coreclr)\.dll$', 'i')
  AND ((REGEXP_LIKE(process_path, '\\(rundll32|dllhost|regsvr32|werfault|searchprotocolhost|gpupdate|spoolsv|notepad|svchost|wuauclt|mstsc)\.exe$', 'i')) OR (process_signed = FALSE AND process_prevalence = 'RARE'));
