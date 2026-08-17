-- source_yaral: detections/mimikatz/yaral/mimikatz_clipboard_device_access.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: mimikatz_clipboard_device_access
-- severity: low
-- procedure_ids: P34,P42
-- description: Surfaces vendor-reported clipboard or smartcard HID RF device access.
-- log_source_prerequisites: EDR clipboard or device-control telemetry with process and device or operation.
-- false_positives: Normal clipboard, smartcard, HID and reader software.
-- references: reports/mimikatz/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'mimikatz_clipboard_device_access' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('*') OR event_type IN ('*')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
