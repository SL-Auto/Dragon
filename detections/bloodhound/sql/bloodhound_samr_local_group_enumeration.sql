-- source_yaral: detections/bloodhound/yaral/bloodhound_samr_local_group_enumeration.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: bloodhound_samr_local_group_enumeration
-- severity: high
-- procedure_ids: BH-009,BH-010
-- description: Detects SAMR or LSA policy read operations against multiple remote hosts.
-- log_source_prerequisites: NDR or EDR RPC telemetry exposing SAMR/LSA interface or operation and source/target identity.
-- false_positives: Asset inventory, compliance scanners and endpoint-management systems.
-- references: reports/bloodhound/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'bloodhound_samr_local_group_enumeration' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('RPC_CALL') OR event_type IN ('RPC_CALL')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
