-- source_yaral: detections/adaptixc2/yaral/adaptix_raw_socket_dns_from_user_process.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: adaptix_raw_socket_dns_from_user_process
-- severity: high
-- procedure_ids: AX-P02
-- description: Detects a user-mode process other than the Windows DNS Client sending recurrent UDP/53 traffic directly to a resolver (six or more connections across four or more minutes within 30 minutes). This is the raw-socket DNS transport, which bypasses the DNS Client service and Sysmon DNS query logging.
-- log_source_prerequisites: Process-attributed NETWORK_CONNECTION telemetry (Sysmon Event ID 3 or EDR) with direction, protocol, destination IP and port, host and stable process ID; optional signature verification status. UDP must be logged.
-- false_positives: Security agents, VPN clients and browsers with built-in DNS-over-UDP resolvers; approve by signer.
-- references: reports/adaptixc2/source-analysis.md#procedure-analysis; reviews/adaptixc2/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, direction, hostname, process_id, process_path, target_ip, target_port, ip_protocol, process_signed); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by hostname, process_id and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, direction, hostname, process_id, process_path, target_ip, target_port, ip_protocol, process_signed.
SELECT hostname, process_id, COUNT(*) AS matched_count, 'adaptix_raw_socket_dns_from_user_process' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND event_type = 'NETWORK_CONNECTION'
  AND target_port = 53
  AND ip_protocol = 'UDP'
  AND NOT REGEXP_LIKE(COALESCE(process_path, ''), '\\windows\\system32\\(svchost|dns|lsass)\.exe$', 'i')
  AND COALESCE(process_signed, FALSE) = FALSE
GROUP BY hostname, process_id
HAVING COUNT(*) >= 6;
