-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_socket_listen_or_rare_egress_compensating_signal.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cobalt_strike_socket_listen_or_rare_egress_compensating_signal
-- severity: high
-- procedure_ids: CSB-008
-- description: Correlates a rare-process socket listen with an accepted inbound connection on the same port and process, closing the gap between merely listening and actually receiving a connection that the base standalone-listen rule leaves open.
-- log_source_prerequisites: Normalize SOCKET_LISTEN and inbound NETWORK_CONNECTION with a stable vendor process identifier (product_specific_process_id), process signer/prevalence, and port, joined on host, process and port within 30 minutes, listen first.
-- false_positives: Development tools and local services that legitimately listen from rare binaries and receive local or authorized connections.
-- references: reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_socket_listen_or_rare_egress.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, hostname, direction, process_id, target_process_id, target_port, process_signed, process_prevalence); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native ordered two-event correlation on hostname, listen_process, target_port within 30 minutes (first event before second). Exact per-pair self-join; regex, REGEXP_SUBSTR and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, hostname, direction, process_id, target_process_id, target_port, process_signed, process_prevalence.
WITH first_leg AS (
  SELECT *, process_id AS listen_process FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
    AND event_type = 'SOCKET_LISTEN'
    AND ((process_signed = FALSE) OR (process_prevalence = 'RARE'))
 ),
second_leg AS (
  SELECT *, target_process_id AS listen_process FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
    AND event_type = 'NETWORK_CONNECTION'
    AND direction = 'INBOUND'
)
SELECT a.hostname, a.listen_process, a.target_port, MIN(a.event_time) AS first_time, MAX(b.event_time) AS last_time, 'cobalt_strike_socket_listen_or_rare_egress_compensating_signal' AS canonical_rule
FROM first_leg a
JOIN second_leg b
  ON a.hostname = b.hostname
 AND a.listen_process = b.listen_process
 AND a.target_port = b.target_port
 AND b.event_time BETWEEN a.event_time AND a.event_time + INTERVAL '30' MINUTE
GROUP BY a.hostname, a.listen_process, a.target_port;
