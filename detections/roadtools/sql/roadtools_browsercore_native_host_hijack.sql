-- source_yaral: detections/roadtools/yaral/roadtools_browsercore_native_host_hijack.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: roadtools_browsercore_native_host_hijack
-- severity: high
-- procedure_ids: RT-P12
-- description: Detects registration or creation of a com.microsoft.browsercore native-messaging host whose manifest path is not the Microsoft BrowserCore executable, the fake host that signs PRT cookies from a stolen PRT.
-- log_source_prerequisites: REGISTRY_MODIFICATION (Sysmon Event ID 13) for NativeMessagingHosts keys, and FILE_CREATION (Sysmon Event ID 11) for manifest and BrowserCore.py files, with host and process.
-- false_positives: None expected outside security research.
-- references: reports/roadtools/source-analysis.md#procedure-analysis; reviews/roadtools/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, hostname, registry_key, registry_value_data, target_path); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by hostname and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, hostname, registry_key, registry_value_data, target_path.
SELECT hostname, COUNT(*) AS matched_count, 'roadtools_browsercore_native_host_hijack' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND ((event_type = 'REGISTRY_MODIFICATION' AND REGEXP_LIKE(registry_key, '\NativeMessagingHosts\com\.microsoft\.browsercore', 'i') AND NOT REGEXP_LIKE(COALESCE(registry_value_data, ''), '\Windows\BrowserCore\manifest\.json', 'i')) OR (event_type = 'FILE_CREATION' AND REGEXP_LIKE(target_path, '\BrowserCore\.py$', 'i')))
GROUP BY hostname
HAVING COUNT(*) >= 1;
