-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_socket_fanout_or_forwarding_compensating_signal.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cobalt_strike_socket_fanout_or_forwarding_compensating_signal
-- severity: high
-- procedure_ids: CSB-009
-- description: Correlates an inbound connection to a process with that same process subsequently creating multiple distinct outbound connections, detecting the relay/forwarding topology that the base outbound-only fan-out rule cannot express.
-- log_source_prerequisites: Normalize NETWORK_CONNECTION for both inbound and outbound direction with a stable vendor process identifier (product_specific_process_id), joined on host and process within 15 minutes, inbound first.
-- false_positives: Browsers, approved proxies, EDR, backup, and orchestration agents that legitimately combine inbound acceptance with outbound fan-out.
-- references: reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_socket_fanout_or_forwarding.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, hostname, direction, process_id, target_process_id, target_ip); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native ordered two-event correlation on hostname, relay_process within 15 minutes (first event before second). Exact per-pair self-join; regex, REGEXP_SUBSTR and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, hostname, direction, process_id, target_process_id, target_ip.
WITH first_leg AS (
  SELECT *, target_process_id AS relay_process FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
    AND event_type = 'NETWORK_CONNECTION'
    AND direction = 'INBOUND'
 ),
second_leg AS (
  SELECT *, process_id AS relay_process FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
    AND event_type = 'NETWORK_CONNECTION'
    AND direction = 'OUTBOUND'
)
SELECT a.hostname, a.relay_process, MIN(a.event_time) AS first_time, MAX(b.event_time) AS last_time, COUNT(DISTINCT b.target_ip) AS matched_count, 'cobalt_strike_socket_fanout_or_forwarding_compensating_signal' AS canonical_rule
FROM first_leg a
JOIN second_leg b
  ON a.hostname = b.hostname
 AND a.relay_process = b.relay_process
 AND b.event_time BETWEEN a.event_time AND a.event_time + INTERVAL '15' MINUTE
GROUP BY a.hostname, a.relay_process
HAVING COUNT(DISTINCT b.target_ip) >= 5;
