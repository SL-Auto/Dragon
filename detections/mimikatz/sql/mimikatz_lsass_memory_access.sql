-- source_yaral: detections/mimikatz/yaral/mimikatz_lsass_memory_access.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: mimikatz_lsass_memory_access
-- severity: high
-- procedure_ids: P07,P09,P13
-- description: Detects process access to LSASS with memory-read-capable rights; tuning is applied downstream rather than with broad process-name exclusions.
-- log_source_prerequisites: Normalize Sysmon Event ID 10 or equivalent EDR process-open telemetry to UDM with source and target process paths and access-mask text.
-- false_positives: EDR and antivirus sensors, approved diagnostics, authentication extensions, and accessibility tooling.
-- references: reports/mimikatz/source-analysis.md; https://learn.microsoft.com/windows/security/operating-system-security/sysmon/sysmon-events
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'mimikatz_lsass_memory_access' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('10', 'PROCESS_OPEN') OR event_type IN ('10', 'PROCESS_OPEN')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
