-- source_yaral: detections/sliver/yaral/sliver_registry_from_network_process.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: sliver_registry_from_network_process
-- severity: medium
-- procedure_ids: PROC-018
-- description: Registry mutation by a process with outbound network activity
-- log_source_prerequisites: Registry mutation and network UDM with stable PID
-- false_positives: Installers, management, security software
-- references: reports/sliver/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'sliver_registry_from_network_process' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION', 'REGISTRY_MODIFICATION') OR event_type IN ('NETWORK_CONNECTION', 'REGISTRY_MODIFICATION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
