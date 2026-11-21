-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_file_cleanup_or_timestomp_compensating_signal.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cobalt_strike_file_cleanup_or_timestomp_compensating_signal
-- severity: medium
-- procedure_ids: CSB-026,CSB-034
-- description: Correlates execution of a file with deletion of that same file path by an unsigned or rare process shortly afterward, covering self-deleting-artifact cleanup that the base rarity-only rule does not tie to prior execution.
-- log_source_prerequisites: Normalize PROCESS_LAUNCH and FILE_DELETE with matching full path, host, and process signer/prevalence on the deleting process, joined within 15 minutes.
-- false_positives: Installers, updaters, and self-extracting archives remain a false-positive source when they are unsigned or rare; the signer/prevalence gate narrows but does not eliminate this overlap.
-- references: reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_file_cleanup_or_timestomp.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, hostname, target_process_path, target_path, process_signed, process_prevalence); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native ordered two-event correlation on hostname, file_path within 15 minutes (first event before second). Exact per-pair self-join; regex, REGEXP_SUBSTR and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, hostname, target_process_path, target_path, process_signed, process_prevalence.
WITH first_leg AS (
  SELECT *, target_process_path AS file_path FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
    AND event_type = 'PROCESS_LAUNCH'
 ),
second_leg AS (
  SELECT *, target_path AS file_path FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
    AND event_type IN ('FILE_DELETION', 'FILE_DELETE')
    AND ((process_signed = FALSE) OR (process_prevalence = 'RARE'))
)
SELECT a.hostname, a.file_path, MIN(a.event_time) AS first_time, MAX(b.event_time) AS last_time, 'cobalt_strike_file_cleanup_or_timestomp_compensating_signal' AS canonical_rule
FROM first_leg a
JOIN second_leg b
  ON a.hostname = b.hostname
 AND a.file_path = b.file_path
 AND b.event_time BETWEEN a.event_time AND a.event_time + INTERVAL '15' MINUTE
GROUP BY a.hostname, a.file_path;
