-- source_yaral: detections/mimikatz/yaral/mimikatz_firmware_driver_operation.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: mimikatz_firmware_driver_operation
-- severity: high
-- procedure_ids: P39,P43
-- description: Detects firmware-variable or kernel-driver activity reported by endpoint controls.
-- log_source_prerequisites: EDR firmware or driver telemetry and Code Integrity events with process and module identity.
-- false_positives: Firmware management, OEM tools and approved drivers.
-- references: reports/mimikatz/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'mimikatz_firmware_driver_operation' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('6') OR event_type IN ('6')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
