-- source_yaral: detections/impacket/yaral/impacket_rapid_scheduled_task_create_and_run.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: impacket_rapid_scheduled_task_create_and_run
-- severity: high
-- procedure_ids: IMP-04
-- description: Correlates rapid scheduled-task registration and execution; deletion is not required because cleanup may fail or telemetry may be missing.
-- log_source_prerequisites: Normalize Task Scheduler Operational or Security 4698/4699 events with task name, host, action, user, and timestamp.
-- false_positives: Installers, enterprise schedulers, deployment systems, and ephemeral maintenance tasks.
-- references: reports/impacket/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'impacket_rapid_scheduled_task_create_and_run' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('*') OR event_type IN ('*')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
