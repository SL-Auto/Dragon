-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_named_pipe_peer_activity_compensating_signal.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cobalt_strike_named_pipe_peer_activity_compensating_signal
-- severity: high
-- procedure_ids: CSB-007
-- description: Correlates a remote SMB connection to IPC$ with a subsequent rare local pipe connect on the same host, closing the ordered remote-peer branch that the standalone pipe-rarity base rule does not capture.
-- log_source_prerequisites: Normalize NETWORK_CONNECTION to TCP/445 with source/target hostname, plus NAMED_PIPE_CONNECTION (Sysmon 18 or EDR pipe connect) with a pipe-rarity enrichment field, joined on source-to-target host within 5 minutes, SMB connection first.
-- false_positives: Remote administration frameworks, backup/replication agents, and clustered service frameworks that legitimately combine SMB sessions with rare local pipes.
-- references: reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_named_pipe_peer_activity.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, hostname, target_host, target_port, pipe_prevalence, pipe_name); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native ordered two-event correlation on peer_host within 5 minutes (first event before second). Exact per-pair self-join; regex, REGEXP_SUBSTR and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, hostname, target_host, target_port, pipe_prevalence, pipe_name.
WITH first_leg AS (
  SELECT *, target_host AS peer_host FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE
    AND event_type = 'NETWORK_CONNECTION'
    AND target_port = 445
 ),
second_leg AS (
  SELECT *, hostname AS peer_host FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE
    AND event_type IN ('NAMED_PIPE_CONNECTION', 'PIPE_CONNECT')
    AND pipe_prevalence = 'RARE'
)
SELECT a.peer_host, MIN(a.event_time) AS first_time, MAX(b.event_time) AS last_time, 'cobalt_strike_named_pipe_peer_activity_compensating_signal' AS canonical_rule
FROM first_leg a
JOIN second_leg b
  ON a.peer_host = b.peer_host
 AND b.event_time BETWEEN a.event_time AND a.event_time + INTERVAL '5' MINUTE
GROUP BY a.peer_host;
