-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_privileged_context_change_compensating_signal.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cobalt_strike_privileged_context_change_compensating_signal
-- severity: high
-- procedure_ids: CSB-011
-- description: Correlates SeDebugPrivilege enablement on a process with that same process subsequently opening a protected process (lsass.exe or winlogon.exe), closing the causal gap left by the base rule's standalone 4672/token-change signal.
-- log_source_prerequisites: Normalize TOKEN_PRIVILEGE_CHANGE with the enabled privilege name, and PROCESS_OPEN with target image path, joined on host and PID within 10 minutes.
-- false_positives: EDR, debuggers, backup/VSS tooling, and administrative diagnostic utilities that enable SeDebugPrivilege before inspecting system processes.
-- references: reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_privileged_context_change.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, hostname, process_id, privilege_name, target_process_path); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native ordered two-event correlation on hostname, process_id within 10 minutes (first event before second). Exact per-pair self-join; regex, REGEXP_SUBSTR and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, hostname, process_id, privilege_name, target_process_path.
WITH first_leg AS (
  SELECT * FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '20' MINUTE
    AND event_type = 'TOKEN_PRIVILEGE_CHANGE'
    AND privilege_name = 'SeDebugPrivilege'
 ),
second_leg AS (
  SELECT * FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '20' MINUTE
    AND event_type = 'PROCESS_OPEN'
    AND REGEXP_LIKE(target_process_path, '\\(lsass|winlogon)\.exe$', 'i')
)
SELECT a.hostname, a.process_id, MIN(a.event_time) AS first_time, MAX(b.event_time) AS last_time, 'cobalt_strike_privileged_context_change_compensating_signal' AS canonical_rule
FROM first_leg a
JOIN second_leg b
  ON a.hostname = b.hostname
 AND a.process_id = b.process_id
 AND b.event_time BETWEEN a.event_time AND a.event_time + INTERVAL '10' MINUTE
GROUP BY a.hostname, a.process_id;
