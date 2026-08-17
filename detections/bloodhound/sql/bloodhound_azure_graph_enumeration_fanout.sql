-- source_yaral: detections/bloodhound/yaral/bloodhound_azure_graph_enumeration_fanout.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: bloodhound_azure_graph_enumeration_fanout
-- severity: high
-- procedure_ids: BH-017
-- description: Detects one cloud principal reading many Microsoft Graph directory resource families.
-- log_source_prerequisites: MicrosoftGraphActivityLogs with principal/app, source, request URI/resource family, method and result.
-- false_positives: Identity governance, synchronization, compliance and cloud security posture tools.
-- references: reports/bloodhound/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'bloodhound_azure_graph_enumeration_fanout' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('MicrosoftGraphActivityLogs') OR event_type IN ('MicrosoftGraphActivityLogs')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
