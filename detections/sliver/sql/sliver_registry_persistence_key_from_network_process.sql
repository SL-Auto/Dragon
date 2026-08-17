-- source_yaral: detections/sliver/yaral/sliver_registry_persistence_key_from_network_process.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: sliver_registry_persistence_key_from_network_process
-- severity: high
-- procedure_ids: PROC-018
-- description: A network-active process writes a registry key commonly used for persistence or security-control tampering
-- log_source_prerequisites: Registry mutation telemetry with full key path, plus process-attributed network telemetry sharing a stable process entity
-- false_positives: Installers, endpoint management, and security software that legitimately write persistence-adjacent keys
-- references: reports/sliver/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'sliver_registry_persistence_key_from_network_process' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('REGISTRY_MODIFICATION', 'NETWORK_CONNECTION') OR event_type IN ('REGISTRY_MODIFICATION', 'NETWORK_CONNECTION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
