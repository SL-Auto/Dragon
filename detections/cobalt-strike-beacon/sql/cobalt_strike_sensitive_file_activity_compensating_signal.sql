-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_sensitive_file_activity_compensating_signal.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cobalt_strike_sensitive_file_activity_compensating_signal
-- severity: high
-- procedure_ids: CSB-024,CSB-025
-- description: Aggregates sensitive-file reads by user and host across processes and correlates them with archive creation by the same user/host, covering multi-process collection where one process stages files and another compresses or transmits them.
-- log_source_prerequisites: Normalize FILE_READ with sensitivity classification, and FILE_CREATION/FILE_MODIFICATION for archive-extension targets, joined on host and user within 30 minutes, at least one read before the archive write.
-- false_positives: Backup, synchronization, DLP, indexing, and document-management tools that read multiple sensitive files and then write compressed archives.
-- references: reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_sensitive_file_activity.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, hostname, user_id, target_path, file_sensitivity); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native ordered two-event correlation on hostname, user_id within 30 minutes (first event before second). Exact per-pair self-join; regex, REGEXP_SUBSTR and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, hostname, user_id, target_path, file_sensitivity.
WITH first_leg AS (
  SELECT * FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
    AND event_type = 'FILE_READ'
    AND file_sensitivity = 'HIGH'
 ),
second_leg AS (
  SELECT * FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
    AND event_type IN ('FILE_CREATION', 'FILE_MODIFICATION', 'FILE_WRITE')
    AND REGEXP_LIKE(target_path, '\.(zip|7z|rar)$', 'i')
)
SELECT a.hostname, a.user_id, MIN(a.event_time) AS first_time, MAX(b.event_time) AS last_time, COUNT(DISTINCT a.target_path) AS matched_count, 'cobalt_strike_sensitive_file_activity_compensating_signal' AS canonical_rule
FROM first_leg a
JOIN second_leg b
  ON a.hostname = b.hostname
 AND a.user_id = b.user_id
 AND b.event_time BETWEEN a.event_time AND a.event_time + INTERVAL '30' MINUTE
GROUP BY a.hostname, a.user_id
HAVING COUNT(DISTINCT a.target_path) >= 5;
