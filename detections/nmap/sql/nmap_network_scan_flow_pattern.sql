-- source_yaral: detections/nmap/yaral/nmap_network_scan_flow_pattern.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: nmap_network_scan_flow_pattern
-- severity: medium
-- procedure_ids: NM-P01,NM-P03,NM-P04,NM-P06
-- description: Detects one internal source IP probing one hundred or more distinct destination ports on a host, or one hundred or more hosts, within 5 minutes in network flow telemetry, covering raw and half-open scans that endpoint sensors do not attribute to a process.
-- log_source_prerequisites: NDR, firewall or flow telemetry (NETWORK_CONNECTION or NETWORK_FLOW without process) with source IP, destination IP and port; denied and reset flows retained.
-- false_positives: Vulnerability scanners, network monitoring and load-balancer health checks; approve scanner IPs.
-- references: reports/nmap/source-analysis.md#procedure-analysis; reviews/nmap/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, source_ip, target_ip, target_port); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by source_ip and threshold. Hop window approximated by scheduling every 5 minutes over the trailing 5 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, source_ip, target_ip, target_port.
SELECT source_ip, COUNT(DISTINCT target_ip) AS matched_count, 'nmap_network_scan_flow_pattern' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '5' MINUTE
  AND event_type IN ('NETWORK_CONNECTION', 'NETWORK_FLOW')
  AND REGEXP_LIKE(source_ip, '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)', 'i')
GROUP BY source_ip
HAVING COUNT(DISTINCT target_ip) >= 100;
