-- source_yaral: detections/chisel/yaral/chisel_proxy_destination_fanout.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: chisel_proxy_destination_fanout
-- severity: high
-- procedure_ids: CH-P05,CH-P07
-- description: Detects one uncommon process connecting to many destinations after listener activity consistent with a dynamic proxy
-- log_source_prerequisites: EDR socket listen and outbound connection telemetry with process prevalence enrichment
-- false_positives: Browsers update agents security scanners service meshes and approved proxies
-- references: reports/chisel/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'chisel_proxy_destination_fanout' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION', 'NETWORK_LISTEN') OR event_type IN ('NETWORK_CONNECTION', 'NETWORK_LISTEN')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
