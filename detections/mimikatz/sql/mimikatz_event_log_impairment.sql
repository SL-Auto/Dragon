-- source_yaral: detections/mimikatz/yaral/mimikatz_event_log_impairment.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: mimikatz_event_log_impairment
-- severity: high
-- procedure_ids: P26
-- description: Detects log clearing or endpoint telemetry reporting Event Log service tampering.
-- log_source_prerequisites: Forwarded Security 1102, System 104 or EDR service-tamper telemetry.
-- false_positives: Authorized log maintenance and lab reset.
-- references: reports/mimikatz/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'mimikatz_event_log_impairment' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('104', '1102') OR event_type IN ('104', '1102')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
