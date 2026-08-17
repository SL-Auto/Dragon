-- source_yaral: detections/sliver/yaral/sliver_explicit_credential_service_creation.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: sliver_explicit_credential_service_creation
-- severity: high
-- procedure_ids: PROC-016,PROC-017,PROC-019
-- description: An explicit-credential logon is followed by a service or task creation performed as that credentialed account on the same host
-- log_source_prerequisites: Windows explicit-credential logon and service/task-creation events correlated by target account and host, plus process-attributed network telemetry on the same host
-- false_positives: Software deployment tooling, backup agents, and authorized administrators who run-as another account before installing a service
-- references: reports/sliver/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'sliver_explicit_credential_service_creation' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4648', '4697', '7045', 'NETWORK_CONNECTION') OR event_type IN ('4648', '4697', '7045', 'NETWORK_CONNECTION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
