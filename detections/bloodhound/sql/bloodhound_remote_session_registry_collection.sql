-- source_yaral: detections/bloodhound/yaral/bloodhound_remote_session_registry_collection.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: bloodhound_remote_session_registry_collection
-- severity: high
-- procedure_ids: BH-007,BH-008
-- description: Correlates SRVSVC session enumeration or remote registry reads with multi-host SMB/RPC activity.
-- log_source_prerequisites: NDR/EDR RPC interface or REGISTRY_READ telemetry plus source identity and target host.
-- false_positives: Endpoint inventory, helpdesk, EDR and authorized administration.
-- references: reports/bloodhound/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'bloodhound_remote_session_registry_collection' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('REGISTRY_READ', 'RPC_CALL') OR event_type IN ('REGISTRY_READ', 'RPC_CALL')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
