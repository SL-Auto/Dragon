-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_credential_access_effect_compensating_signal.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cobalt_strike_credential_access_effect_compensating_signal
-- severity: high
-- procedure_ids: CSB-028
-- description: Correlates dangerous-rights LSASS process access with creation of a memory-dump artifact by the same process, narrowing the broad LSASS/store/replication effect rule to an ordered access-plus-artifact sequence.
-- log_source_prerequisites: Normalize EDR PROCESS_OPEN against lsass.exe with a granted-access/dangerous-rights enrichment field, plus FILE_CREATION for .dmp/.mdmp targets, joined on host and process ID (stable vendor process ID preferred) within a 5-minute window, open before dump.
-- false_positives: EDR/AV LSASS scanners, Procdump-based support workflows, Windows Error Reporting crash dumps, and forensic acquisition tools that also create .dmp files.
-- references: reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_credential_access_effect.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, hostname, process_id, target_process_path, dangerous_memory_rights, target_path); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native ordered two-event correlation on hostname, process_id within 5 minutes (first event before second). Exact per-pair self-join; regex, REGEXP_SUBSTR and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, hostname, process_id, target_process_path, dangerous_memory_rights, target_path.
WITH first_leg AS (
  SELECT * FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE
    AND event_type = 'PROCESS_OPEN'
    AND REGEXP_LIKE(target_process_path, '\\lsass\.exe$', 'i')
    AND dangerous_memory_rights = 'true'
 ),
second_leg AS (
  SELECT * FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE
    AND event_type = 'FILE_CREATION'
    AND REGEXP_LIKE(target_path, '\.(dmp|mdmp)$', 'i')
)
SELECT a.hostname, a.process_id, MIN(a.event_time) AS first_time, MAX(b.event_time) AS last_time, 'cobalt_strike_credential_access_effect_compensating_signal' AS canonical_rule
FROM first_leg a
JOIN second_leg b
  ON a.hostname = b.hostname
 AND a.process_id = b.process_id
 AND b.event_time BETWEEN a.event_time AND a.event_time + INTERVAL '5' MINUTE
GROUP BY a.hostname, a.process_id;
