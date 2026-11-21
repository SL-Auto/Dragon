-- source_yaral: detections/nmap/yaral/nmap_broadcast_discovery_ports.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: nmap_broadcast_discovery_ports
-- severity: medium
-- procedure_ids: NM-P11
-- description: Detects one non-system process sending to four or more distinct local discovery protocols (LLMNR 5355, mDNS 5353, SSDP 1900, NBNS 137, DHCP 67, WS-Discovery 3702, SLP 427) within 2 minutes, the pattern of NSE broadcast scripts.
-- log_source_prerequisites: Process-attributed NETWORK_CONNECTION telemetry (Sysmon Event ID 3 or EDR) with destination IP and port, host and stable process ID; optional signature verification status. UDP to multicast or broadcast destinations must be logged.
-- false_positives: Media and device-discovery applications and network inventory tools.
-- references: reports/nmap/source-analysis.md#procedure-analysis; reviews/nmap/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, hostname, process_id, process_path, target_port); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by hostname, process_id and threshold. Hop window approximated by scheduling every 5 minutes over the trailing 2 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, hostname, process_id, process_path, target_port.
SELECT hostname, process_id, COUNT(DISTINCT target_port) AS matched_count, 'nmap_broadcast_discovery_ports' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '2' MINUTE
  AND event_type = 'NETWORK_CONNECTION'
  AND target_port IN ('5355', '5353', '1900', '137', '67', '3702', '427')
  AND NOT REGEXP_LIKE(COALESCE(process_path, ''), '\\windows\\system32\\(svchost|lsass|services|dashost)\.exe$', 'i')
GROUP BY hostname, process_id
HAVING COUNT(DISTINCT target_port) >= 4;
