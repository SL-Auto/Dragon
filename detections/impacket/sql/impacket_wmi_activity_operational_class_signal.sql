-- source_yaral: detections/impacket/yaral/impacket_wmi_activity_operational_class_signal.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: impacket_wmi_activity_operational_class_signal
-- severity: medium
-- procedure_ids: IMP-05
-- description: Detects a remote WMI method invocation against the Win32_Process class observed directly in the WMI-Activity Operational log, independent of whether a WmiPrvSE child process was collected.
-- log_source_prerequisites: WMI-Activity Operational 5857/5858/5860/5861 with the operation text parsed into a class label and the caller (ClientMachine) normalized to principal.hostname. Successful Win32_Process.Create calls are not logged by WMI-Activity; this rule sees mainly 5858 failures and 5860/5861 subscription records (review REVIEW-012).
-- false_positives: Endpoint management, inventory, remediation, monitoring agents and any authorized WMI administration that creates or queries Win32_Process; this event family is high-volume and requires tenant baselining before enforcement.
-- references: reports/impacket/source-analysis.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, hostname, source_ip, wmi_class); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by hostname and threshold. Hop window approximated by scheduling every 5 minutes over the trailing 10 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, hostname, source_ip, wmi_class.
SELECT hostname, COUNT(*) AS matched_count, 'impacket_wmi_activity_operational_class_signal' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE
  AND product_event_type IN ('5857', '5858', '5860', '5861')
  AND REGEXP_LIKE(wmi_class, 'Win32_Process', 'i')
GROUP BY hostname
HAVING COUNT(*) >= 1;
