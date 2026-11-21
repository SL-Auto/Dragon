-- source_yaral: detections/nmap/yaral/nmap_process_connect_scan_fanout.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: nmap_process_connect_scan_fanout
-- severity: medium
-- procedure_ids: NM-P02,NM-P05,NM-P08
-- description: Detects one unverified process opening outbound connections to fifty or more distinct internal hosts, or fifty or more distinct ports, within 5 minutes, the host effect of a connect scan, version probing or script scanning.
-- log_source_prerequisites: Process-attributed NETWORK_CONNECTION telemetry (Sysmon Event ID 3 or EDR) with destination IP and port, host and stable process ID; optional signature verification status.
-- false_positives: Approved vulnerability scanners, asset-discovery agents and monitoring systems.
-- references: reports/nmap/source-analysis.md#procedure-analysis; reviews/nmap/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, direction, hostname, process_id, process_path, target_ip, target_port, process_signed); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by hostname, process_id and threshold. Hop window approximated by scheduling every 5 minutes over the trailing 5 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, direction, hostname, process_id, process_path, target_ip, target_port, process_signed.
SELECT hostname, process_id, COUNT(DISTINCT target_ip) AS matched_count, 'nmap_process_connect_scan_fanout' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '5' MINUTE
  AND event_type = 'NETWORK_CONNECTION'
  AND direction = 'OUTBOUND'
  AND REGEXP_LIKE(target_ip, '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|f[cd][0-9a-f]{2}:)', 'i')
  AND COALESCE(process_signed, FALSE) = FALSE
GROUP BY hostname, process_id
HAVING COUNT(DISTINCT target_ip) >= 50;
