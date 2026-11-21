-- source_yaral: detections/adaptixc2/yaral/adaptix_recurrent_process_egress.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: adaptix_recurrent_process_egress
-- severity: medium
-- procedure_ids: AX-P01,AX-P04
-- description: Detects an unverified process making five or more outbound connections to the same destination across four or more distinct minutes within 1 hour, the polling of an HTTP(S) or TCP agent transport.
-- log_source_prerequisites: Process-attributed NETWORK_CONNECTION telemetry (Sysmon Event ID 3 or EDR) with direction, protocol, destination IP and port, host and stable process ID; optional signature verification status.
-- false_positives: Unsigned updaters, telemetry agents and custom line-of-business software.
-- references: reports/adaptixc2/source-analysis.md#procedure-analysis; reviews/adaptixc2/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, direction, hostname, process_id, process_path, target_ip, target_port, ip_protocol, process_signed); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by hostname, process_id, target_ip and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, direction, hostname, process_id, process_path, target_ip, target_port, ip_protocol, process_signed.
SELECT hostname, process_id, target_ip, COUNT(*) AS matched_count, 'adaptix_recurrent_process_egress' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND event_type = 'NETWORK_CONNECTION'
  AND direction = 'OUTBOUND'
  AND COALESCE(process_signed, FALSE) = FALSE
GROUP BY hostname, process_id, target_ip
HAVING COUNT(*) >= 5;
