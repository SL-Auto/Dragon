-- source_yaral: detections/bloodhound/yaral/bloodhound_collector_process_network_context.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: bloodhound_collector_process_network_context
-- severity: medium
-- procedure_ids: BH-001
-- description: Detects a low-prevalence process establishing sustained directory or cloud management network context.
-- log_source_prerequisites: EDR process creation and process-attributed network telemetry with signer/prevalence and destination service classification.
-- false_positives: Identity inventory, endpoint management, directory administration and cloud governance tooling.
-- references: reports/bloodhound/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'bloodhound_collector_process_network_context' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION', 'PROCESS_LAUNCH') OR event_type IN ('NETWORK_CONNECTION', 'PROCESS_LAUNCH')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
