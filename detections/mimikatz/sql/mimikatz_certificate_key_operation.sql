-- source_yaral: detections/mimikatz/yaral/mimikatz_certificate_key_operation.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: mimikatz_certificate_key_operation
-- severity: medium
-- procedure_ids: P21,P24
-- description: Surfaces certificate enrollment, private-key export or Hello key operations.
-- log_source_prerequisites: AD CS, CAPI2, Hello, TPM or EDR key-operation telemetry.
-- false_positives: Normal enrollment, renewal, signing and device provisioning.
-- references: reports/mimikatz/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'mimikatz_certificate_key_operation' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4886', '4887') OR event_type IN ('4886', '4887')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
