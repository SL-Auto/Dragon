-- source_yaral: detections/mimikatz/yaral/mimikatz_sensitive_store_access.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: mimikatz_sensitive_store_access
-- severity: medium
-- procedure_ids: P18,P19,P20,P23,P25,P37,P41,P46
-- description: Detects one process reading credential, key, DPAPI, IIS, SCCM, Citrix, browser or RDM stores.
-- log_source_prerequisites: EDR sensitive file or registry read telemetry with process and target path.
-- false_positives: Backup, migration, inventory, browser, credential management and endpoint security software.
-- references: reports/mimikatz/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'mimikatz_sensitive_store_access' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('FILE_READ', 'REGISTRY_READ') OR event_type IN ('FILE_READ', 'REGISTRY_READ')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
