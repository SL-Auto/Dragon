-- source_yaral: detections/impacket/yaral/impacket_remote_registry_activity.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: impacket_remote_registry_activity
-- severity: high
-- procedure_ids: IMP-14
-- description: Detects remote registry service activation or sensitive key changes.
-- log_source_prerequisites: Service, registry and RPC telemetry with key, actor and source.
-- false_positives: Inventory, backup and remote support.
-- references: reports/impacket/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'impacket_remote_registry_activity' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('12', '13', '14') OR event_type IN ('12', '13', '14')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
