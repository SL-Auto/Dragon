-- source_yaral: detections/ligolo-ng/yaral/ligolo_process_internal_admin_port_sweep.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: ligolo_process_internal_admin_port_sweep
-- severity: medium
-- procedure_ids: LG-P02,LG-P04
-- description: Detects one unverified process connecting to many distinct internal hosts on administrative service ports within 10 minutes, without requiring a visible tunnel leg. It compensates for pivots whose upstream is an internal proxy, a chained agent or an inbound session that the parser cannot orient.
-- log_source_prerequisites: Process-attributed OUTBOUND NETWORK_CONNECTION telemetry (Sysmon Event ID 3 or EDR) with destination IP and port, host and stable process ID; optional signature verification status.
-- false_positives: Unapproved or unsigned inventory, vulnerability and monitoring scanners and custom administration scripts; approve scanner images and hosts.
-- references: reports/ligolo-ng/source-analysis.md#procedure-analysis; public-rules/comparisons/ligolo-ng/ligolo_tunnel_process_internal_fanout.md; reviews/ligolo-ng/detection-review.md#lg-dr-10
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, direction, hostname, process_id, process_path, target_ip, target_port, process_signed); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by hostname, process_id and threshold. Hop window approximated by scheduling every 5 minutes over the trailing 10 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, direction, hostname, process_id, process_path, target_ip, target_port, process_signed.
SELECT hostname, process_id, COUNT(DISTINCT target_ip) AS matched_count, 'ligolo_process_internal_admin_port_sweep' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE
  AND event_type = 'NETWORK_CONNECTION'
  AND direction = 'OUTBOUND'
  AND target_port IN ('21', '22', '23', '135', '139', '445', '3389', '5985', '5986')
  AND REGEXP_LIKE(target_ip, '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|f[cd][0-9a-f]{2}:)', 'i')
  AND COALESCE(process_signed, FALSE) = FALSE
GROUP BY hostname, process_id
HAVING COUNT(DISTINCT target_ip) >= 30;
