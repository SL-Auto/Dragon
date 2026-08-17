-- source_yaral: detections/bloodhound/yaral/bloodhound_azure_resource_enumeration_fanout.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: bloodhound_azure_resource_enumeration_fanout
-- severity: high
-- procedure_ids: BH-018
-- description: Detects one principal reading many Azure Resource Manager provider and scope families.
-- log_source_prerequisites: ARM read-plane, AzureActivity or gateway audit with principal, source, operation, provider and scope.
-- false_positives: CSPM, cloud inventory, cost management and governance automation.
-- references: reports/bloodhound/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'bloodhound_azure_resource_enumeration_fanout' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('AZURE_RESOURCE_READ', 'AzureActivity') OR event_type IN ('AZURE_RESOURCE_READ', 'AzureActivity')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
