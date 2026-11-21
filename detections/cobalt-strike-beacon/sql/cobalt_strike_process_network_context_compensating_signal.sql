-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_process_network_context_compensating_signal.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cobalt_strike_process_network_context_compensating_signal
-- severity: high
-- procedure_ids: CSB-001,CSB-002,CSB-005
-- description: Detects low-variance periodic outbound connections from a rare-prevalence process to a rare destination, adding the classic beacon-interval and destination-novelty dimensions that the base rarity-only fan-in rule does not measure.
-- log_source_prerequisites: Normalize NETWORK_CONNECTION with process hash and prevalence, destination hostname and a destination-prevalence enrichment, and an interval-variance-bucket enrichment derived from inter-connection timing.
-- false_positives: Software updaters, telemetry/monitoring agents, and any low-jitter scheduled task that also happens to run from a rare process against a rare destination.
-- references: reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_process_network_context.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, process_sha256, process_prevalence, target_host, interval_variance_bucket, destination_prevalence); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by process_sha256, target_host and threshold. Hop window approximated by scheduling every 40 minutes over the trailing 120 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, process_sha256, process_prevalence, target_host, interval_variance_bucket, destination_prevalence.
SELECT process_sha256, target_host, COUNT(*) AS matched_count, 'cobalt_strike_process_network_context_compensating_signal' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '120' MINUTE
  AND event_type = 'NETWORK_CONNECTION'
  AND process_prevalence = 'RARE'
  AND interval_variance_bucket = 'LOW'
  AND destination_prevalence = 'RARE'
GROUP BY process_sha256, target_host
HAVING COUNT(*) >= 8;
