-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_discovery_fanout_compensating_signal.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cobalt_strike_discovery_fanout_compensating_signal
-- severity: medium
-- procedure_ids: CSB-021
-- description: Aggregates attempted network connections by user and host over a wider window at a lower per-process threshold to surface slow or distributed port/network discovery that falls under the single-process fan-out rule's threshold.
-- log_source_prerequisites: Normalize process-attributed NETWORK_CONNECTION attempts with destination IP/port, account, hostname, and an allowlist enrichment identifying approved scanners.
-- false_positives: Vulnerability scanners, monitoring, software distribution, service discovery and network management tools not present in the approved-scanner enrichment.
-- references: reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_discovery_fanout.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, user_id, hostname, target_ip, target_port, approved_scanner); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by user_id, hostname and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. The canonical rule also requires >=4 distinct ports; SPL/KQL/SQL add that second threshold below the generated one. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, user_id, hostname, target_ip, target_port, approved_scanner.
SELECT user_id, hostname, COUNT(DISTINCT target_ip) AS matched_count, 'cobalt_strike_discovery_fanout_compensating_signal' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND event_type = 'NETWORK_CONNECTION'
  AND COALESCE(approved_scanner, FALSE) = FALSE
GROUP BY user_id, hostname
HAVING COUNT(DISTINCT target_ip) >= 10
   AND COUNT(DISTINCT target_port) >= 4;
