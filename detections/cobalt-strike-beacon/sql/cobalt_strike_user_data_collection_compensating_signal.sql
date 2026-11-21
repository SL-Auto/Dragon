-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_user_data_collection_compensating_signal.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cobalt_strike_user_data_collection_compensating_signal
-- severity: high
-- procedure_ids: CSB-027
-- description: Correlates a user-data collection effect (screen, clipboard, input, or browser-secret) with an outbound network connection from the same process shortly afterward, distinguishing collection-then-egress from a single benign access that the base standalone-effect rule cannot separate.
-- log_source_prerequisites: Normalize vendor SCREEN_CAPTURE/CLIPBOARD_READ/INPUT_CAPTURE/BROWSER_SECRET_READ and outbound NETWORK_CONNECTION with a stable vendor process identifier (product_specific_process_id), joined on host and process within 15 minutes, collection first.
-- false_positives: Assistive technology, conferencing, remote support, password managers, browsers, and approved monitoring software that both collect and transmit data as part of normal operation.
-- references: reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_user_data_collection.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, hostname, process_id, direction); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native ordered two-event correlation on hostname, process_id within 15 minutes (first event before second). Exact per-pair self-join; regex, REGEXP_SUBSTR and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, hostname, process_id, direction.
WITH first_leg AS (
  SELECT * FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
    AND event_type IN ('SCREEN_CAPTURE', 'CLIPBOARD_READ', 'INPUT_CAPTURE', 'BROWSER_SECRET_READ')
 ),
second_leg AS (
  SELECT * FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
    AND event_type = 'NETWORK_CONNECTION'
    AND direction = 'OUTBOUND'
)
SELECT a.hostname, a.process_id, MIN(a.event_time) AS first_time, MAX(b.event_time) AS last_time, 'cobalt_strike_user_data_collection_compensating_signal' AS canonical_rule
FROM first_leg a
JOIN second_leg b
  ON a.hostname = b.hostname
 AND a.process_id = b.process_id
 AND b.event_time BETWEEN a.event_time AND a.event_time + INTERVAL '15' MINUTE
GROUP BY a.hostname, a.process_id;
