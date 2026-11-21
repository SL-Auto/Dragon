-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_file_cleanup_or_timestomp.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: cobalt_strike_file_cleanup_or_timestomp
-- severity: medium
-- procedure_ids: CSB-026,CSB-034
-- description: Detects deletion or timestamp modification by a rare/unsigned process and covers observable teardown artifacts.
-- log_source_prerequisites: Normalize Sysmon 2/23/26 or EDR FILE_DELETE/FILE_TIMESTAMP_CHANGE with process, path, old/new timestamps, signer/prevalence and user.
-- false_positives: Installers, updaters, cleanup utilities, browsers, temporary-file frameworks and backup restore.
-- references: reports/cobalt-strike-beacon/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'cobalt_strike_file_cleanup_or_timestomp' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('2', '23', '26', 'FILE_DELETE', 'FILE_DELETION', 'FILE_TIMESTAMP_CHANGE') OR event_type IN ('2', '23', '26', 'FILE_DELETE', 'FILE_DELETION', 'FILE_TIMESTAMP_CHANGE')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
