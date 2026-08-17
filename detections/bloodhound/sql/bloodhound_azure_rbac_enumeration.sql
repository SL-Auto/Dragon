-- source_yaral: detections/bloodhound/yaral/bloodhound_azure_rbac_enumeration.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: bloodhound_azure_rbac_enumeration
-- severity: high
-- procedure_ids: BH-019
-- description: Detects high-cardinality Azure RBAC, owner, access-policy or role-eligibility reads.
-- log_source_prerequisites: Graph/ARM audit with principal, operation name, target scope/object and source.
-- false_positives: Access reviews, IAM governance, CSPM and authorized audits.
-- references: reports/bloodhound/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'bloodhound_azure_rbac_enumeration' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('AZURE_RESOURCE_READ', 'AzureActivity', 'MicrosoftGraphActivityLogs') OR event_type IN ('AZURE_RESOURCE_READ', 'AzureActivity', 'MicrosoftGraphActivityLogs')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
